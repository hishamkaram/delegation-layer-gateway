package connector

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type request struct {
	command      protocol.Command
	rootOnly     bool
	project      Project
	config       *configuration
	task         protocol.TaskBinding
	admission    *protocol.Admission
	cancellation *protocol.Cancellation
	rangeRequest *protocol.RangeRequest
	barrier      *protocol.OriginBarrierRequest
	inventory    *protocol.OriginInventoryRequest
	reopen       *protocol.OriginReopenRequest
}

func decodeRequest(cfg *configuration, command protocol.Command) (request, error) {
	project, ok := cfg.projects[command.Project]
	if !ok || command.Operation.Validate() != nil {
		return request{}, ErrConfiguration
	}
	r := request{command: command, project: project, config: cfg}
	if err := r.decodeBody(); err != nil {
		return request{}, err
	}
	if command.Operation == protocol.ContextInspect || command.Operation.Administrative() {
		return r, nil
	}
	if r.task.Validate(command.Operation == protocol.ResumeExisting || command.Operation == protocol.ResultChunk) != nil || r.task.Context != project.wireContext() || r.task.Origin.GatewayID != string(cfg.GatewayID) {
		return request{}, ErrConflict
	}
	return r, nil
}

func (r *request) decodeBody() error {
	switch r.command.Operation {
	case protocol.Admit:
		return r.decodeAdmission()
	case protocol.Resolve, protocol.ResumeExisting, protocol.FenceAbsent, protocol.Status, protocol.Collect:
		return r.decodeTask()
	case protocol.Cancel:
		return r.decodeCancellation()
	case protocol.ResultChunk:
		return r.decodeRange()
	case protocol.ContextInspect:
		return r.decodeInspection()
	case protocol.OriginBarrier:
		return r.decodeBarrier()
	case protocol.OriginInventory:
		return r.decodeInventory()
	case protocol.OriginReopen:
		return r.decodeReopen()
	default:
		return ErrEvidence
	}
}

func (r *request) decodeAdmission() error {
	var body protocol.Admission
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil || body.Validate() != nil {
		return ErrEvidence
	}
	r.admission = &body
	r.task = body.Task
	return nil
}

func (r *request) decodeTask() error {
	var body protocol.TaskControl
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil {
		return ErrEvidence
	}
	r.task = body.Task
	return nil
}

func (r *request) decodeCancellation() error {
	var body protocol.Cancellation
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil || body.Validate() != nil {
		return ErrEvidence
	}
	r.cancellation = &body
	r.task = body.Task
	return nil
}

func (r *request) decodeRange() error {
	var body protocol.RangeRequest
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil || body.Validate() != nil {
		return ErrEvidence
	}
	r.rangeRequest = &body
	r.task = body.Task
	return nil
}

func (r *request) decodeInspection() error {
	var body protocol.InspectRequest
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil || body.GatewayID != string(r.config.GatewayID) {
		return ErrConflict
	}
	r.rootOnly = body.RootOnly
	return nil
}

func (r request) matchesRoot(gateway, root string) bool {
	return gateway == string(r.config.GatewayID) && root == r.project.wireContext().Root
}

func (r *request) decodeBarrier() error {
	var body protocol.OriginBarrierRequest
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil || !r.matchesRoot(body.GatewayID, body.ExpectedRoot) {
		return ErrConflict
	}
	if !wireIdentifier(body.RecoveryID) || (body.ExpectedGeneration != "" && !wireIdentifier(body.ExpectedGeneration)) || !wireIdentifier(body.Generation) || body.ExpectedGeneration == body.Generation {
		return ErrConflict
	}
	r.barrier = &body
	return nil
}

func (r *request) decodeInventory() error {
	var body protocol.OriginInventoryRequest
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil || !r.matchesRoot(body.GatewayID, body.ExpectedRoot) {
		return ErrConflict
	}
	if !wireIdentifier(body.Generation) || (body.Cursor != "" && domain.TaskID(body.Cursor).Validate() != nil) || body.Limit < 1 || body.Limit > 100 {
		return ErrConflict
	}
	r.inventory = &body
	return nil
}

func (r *request) decodeReopen() error {
	var body protocol.OriginReopenRequest
	if protocol.DecodeStrict(r.command.Body, &body, protocol.MaxFrameBytes) != nil || !r.matchesRoot(body.GatewayID, body.ExpectedRoot) {
		return ErrConflict
	}
	if !wireIdentifier(body.RecoveryID) || !wireIdentifier(body.Generation) || !digest(body.CompletenessReceipt) {
		return ErrConflict
	}
	r.reopen = &body
	return nil
}

func wireIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", c) {
			return false
		}
	}
	return true
}

func (r request) optionsAllowed(options executionOptions) bool {
	if options.BudgetNanoseconds <= 0 || options.Model.Validate() != nil || options.Effort.Validate() != nil {
		return false
	}
	for _, policy := range r.project.Providers {
		if policy.Provider != options.Provider || options.BudgetNanoseconds > int64(policy.MaxBudgetSeconds)*int64(time.Second) {
			continue
		}
		permission := false
		for _, candidate := range policy.Permissions {
			if string(candidate) == options.Permission {
				permission = true
			}
		}
		if permission && selectionAllowed(options.Model, policy.Models, policy.NativeModel) && selectionAllowed(options.Effort, policy.Efforts, policy.NativeEffort) {
			return true
		}
	}
	return false
}

func selectionAllowed(selection protocol.Selection, allowed []string, native bool) bool {
	if selection.Kind == "native_default" {
		return native && selection.Value == ""
	}
	for _, value := range allowed {
		if selection.Kind == "explicit" && selection.Value == value {
			return true
		}
	}
	return false
}

func admissionOptions(a protocol.Admission) executionOptions {
	return executionOptions{Provider: a.Provider, Permission: a.Permission, BudgetNanoseconds: int64(a.BudgetSeconds) * int64(time.Second), Model: a.Model, Effort: a.Effort}
}

func (r request) common(ctx context.Context, command string, arguments ...string) (invocation, error) {
	duration := r.config.ControlTimeout
	if deadline, ok := ctx.Deadline(); ok {
		duration = min(duration, time.Until(deadline))
	}
	if duration <= 0 {
		return invocation{}, ErrPending
	}
	args := append([]string{command}, arguments...)
	args = append(args, "--root", r.project.Root, "--json", "--control-timeout", duration.String())
	return invocation{command: command, args: args, config: r.config}, nil
}

func (r request) guarded(ctx context.Context, owner *controlOwner, command string, extra ...string) (invocation, error) {
	origin, err := protocol.Encode(r.task.Origin, MaxStdoutBytes)
	if err != nil {
		return invocation{}, ErrEvidence
	}
	file, err := owner.file("origin-"+strconv.Itoa(len(owner.files))+".json", origin)
	if err != nil {
		return invocation{}, err
	}
	flag := "--expected-origin"
	if command == "dispatch" {
		flag = "--origin"
	}
	args := []string{r.task.TaskID, "--expected-root", r.project.RootToken, "--expected-project", r.project.ProjectToken, flag, file}
	if command == "dispatch" {
		args = args[1:]
		args = append(args, "--id", r.task.TaskID)
	}
	if r.task.SpecSHA256 != "" {
		args = append(args, "--expected-spec-sha256", r.task.SpecSHA256)
	}
	args = append(args, extra...)
	return r.common(ctx, command, args...)
}

func (r request) invocation(ctx context.Context, owner *controlOwner) (invocation, error) {
	switch r.command.Operation {
	case protocol.ContextInspect:
		if r.rootOnly {
			return r.common(ctx, "context", "inspect", "--gateway-id", string(r.config.GatewayID))
		}
		return r.common(ctx, "context", "inspect", "--cwd", r.project.Directory, "--gateway-id", string(r.config.GatewayID))
	case protocol.Admit:
		return r.admissionInvocation(ctx, owner)
	case protocol.Resolve:
		return r.guarded(ctx, owner, "resolve")
	case protocol.ResumeExisting:
		return r.guarded(ctx, owner, "resolve", "--resume-admission")
	case protocol.FenceAbsent:
		return r.guarded(ctx, owner, "resolve", "--fence-if-absent")
	case protocol.Status:
		return r.guarded(ctx, owner, "status")
	case protocol.Collect:
		return r.guarded(ctx, owner, "collect", "--watch", "0s")
	case protocol.Cancel:
		return r.guarded(ctx, owner, "cancel", "--id", r.cancellation.CancellationID)
	case protocol.ResultChunk:
		return r.resultInvocation(ctx, owner)
	case protocol.OriginBarrier:
		return r.common(ctx, "origin", "barrier", "--gateway-id", r.barrier.GatewayID, "--recovery-id", r.barrier.RecoveryID, "--expected-generation", r.barrier.ExpectedGeneration, "--generation", r.barrier.Generation, "--expected-root", r.project.RootToken)
	case protocol.OriginInventory:
		return r.common(ctx, "origin", "inventory", "--gateway-id", r.inventory.GatewayID, "--generation", r.inventory.Generation, "--cursor", r.inventory.Cursor, "--limit", strconv.Itoa(r.inventory.Limit), "--expected-root", r.project.RootToken)
	case protocol.OriginReopen:
		return r.common(ctx, "origin", "reopen", "--gateway-id", r.reopen.GatewayID, "--recovery-id", r.reopen.RecoveryID, "--generation", r.reopen.Generation, "--completeness-receipt", r.reopen.CompletenessReceipt, "--expected-root", r.project.RootToken)
	default:
		return invocation{}, ErrEvidence
	}
}

func (r request) admissionInvocation(ctx context.Context, owner *controlOwner) (invocation, error) {
	brief, err := owner.file("brief.txt", []byte(r.admission.Brief))
	if err != nil {
		return invocation{}, err
	}
	args := []string{"--cwd", r.project.Directory, "--brief", brief, "--provider", r.admission.Provider, "--permission", r.admission.Permission, "--budget", (time.Duration(r.admission.BudgetSeconds) * time.Second).String()}
	if r.admission.Model.Kind == "explicit" {
		args = append(args, "--model", r.admission.Model.Value)
	}
	if r.admission.Effort.Kind == "explicit" {
		args = append(args, "--effort", r.admission.Effort.Value)
	}
	return r.guarded(ctx, owner, "dispatch", args...)
}

func (r request) resultInvocation(ctx context.Context, owner *controlOwner) (invocation, error) {
	descriptor := cliDescriptor{Basename: "result.txt", SHA256: r.rangeRequest.Descriptor.SHA256, Length: r.rangeRequest.Descriptor.Length}
	data, err := protocol.Encode(descriptor, MaxStdoutBytes)
	if err != nil {
		return invocation{}, ErrEvidence
	}
	path, err := owner.file("descriptor.json", data)
	if err != nil {
		return invocation{}, err
	}
	call, err := r.guarded(ctx, owner, "result", "--expected-descriptor", path, "--offset", strconv.FormatInt(r.rangeRequest.Offset, 10), "--limit", strconv.Itoa(r.rangeRequest.Limit))
	if err != nil {
		return invocation{}, err
	}
	call.args = append([]string{"result", "read"}, call.args[1:]...)
	return call, nil
}

func briefHash(value string) string {
	digest := domain.Hash([]byte(value))
	return hex.EncodeToString(digest[:])
}
