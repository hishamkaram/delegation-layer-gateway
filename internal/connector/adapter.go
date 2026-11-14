package connector

import (
	"context"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func failure(op protocol.Operation, code string) protocol.Reply {
	return protocol.Reply{Operation: op, Error: &protocol.Failure{Code: code, Retryable: code == "pending" || code == "resource_limit" || code == "device_not_ready"}}
}

func failed(op protocol.Operation, err error) protocol.Reply {
	code := "evidence_invalid"
	switch {
	case errors.Is(err, ErrCapacity):
		code = "resource_limit"
	case errors.Is(err, ErrPending):
		code = "pending"
	case errors.Is(err, ErrConflict):
		code = "context_mismatch"
	case errors.Is(err, ErrConfiguration):
		code = "device_not_ready"
	}
	return failure(op, code)
}

func bodyReply(op protocol.Operation, value any) protocol.Reply {
	data, err := protocol.Encode(value, protocol.MaxFrameBytes)
	if err != nil {
		return failed(op, ErrEvidence)
	}
	return protocol.Reply{Operation: op, Body: data}
}

// Execute joins all CLI and output-copy owners before returning. Caller context
// expiry stops new Start calls but does not kill an accepted public CLI process.
func (a *Adapter) Execute(ctx context.Context, command protocol.Command) protocol.Reply {
	return a.execute(ctx, command, acceptance{generation: a.Generation()})
}

type acceptance struct {
	generation  uint64
	operationID string
	claim       func(context.Context) error
	held        *permit
}

func (a *Adapter) execute(ctx context.Context, command protocol.Command, accepted acceptance) (reply protocol.Reply) {
	held := permit{}
	if accepted.held != nil {
		held = *accepted.held
	} else {
		var err error
		held, err = a.limits.acquire(command.Operation)
		if err != nil {
			return failed(command.Operation, err)
		}
	}
	if accepted.claim != nil {
		if claimErr := accepted.claim(ctx); claimErr != nil {
			held.release()
			return failure(command.Operation, "expired")
		}
	}
	cfg := a.snapshot()
	if cfg.generation != accepted.generation {
		held.release()
		return failed(command.Operation, ErrConflict)
	}
	r, err := a.decodeRequest(ctx, cfg, command)
	if err != nil {
		held.release()
		return failed(command.Operation, err)
	}
	if accepted.claim != nil && r.task.TaskID != "" && r.task.Origin.OperationID != accepted.operationID {
		held.release()
		return failed(command.Operation, ErrConflict)
	}
	if r.admission != nil && !r.optionsAllowed(admissionOptions(*r.admission)) {
		held.release()
		return failure(command.Operation, "forbidden")
	}
	owner, err := a.begin(ctx, cfg)
	if err != nil {
		held.release()
		return failed(command.Operation, err)
	}
	defer func() {
		if settleErr := a.settle(owner, held); settleErr != nil {
			reply = failed(command.Operation, settleErr)
		}
	}()
	return a.executeOwned(ctx, r, owner)
}

func (a *Adapter) executeOwned(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	if r.resolution != nil {
		return a.resolveProject(ctx, r, owner)
	}
	if (r.command.Operation == protocol.Admit || r.command.Operation == protocol.ResumeExisting) && a.Status().CleanupPending != 0 {
		return failed(r.command.Operation, ErrPending)
	}
	if taskControl(r.command.Operation) {
		return a.executeTaskControl(ctx, r, owner)
	}
	if r.rootOnly || r.command.Operation.Administrative() {
		return a.executeRootControl(ctx, r, owner)
	}
	return a.executeProject(ctx, r, owner)
}

func (a *Adapter) executeProject(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	if !existingDirectory(r.project.Directory) {
		a.observeProject(r.config.generation, protocol.ProjectCapability{Alias: r.project.Alias, Context: r.project.wireContext()})
		return failure(r.command.Operation, "device_not_ready")
	}
	probe, err := a.inspect(ctx, r, owner)
	if err != nil {
		a.observeProject(r.config.generation, protocol.ProjectCapability{Alias: r.project.Alias, Context: r.project.wireContext()})
		return failed(r.command.Operation, err)
	}
	a.observeProject(r.config.generation, a.projectReport(r, probe))
	if r.command.Operation == protocol.ContextInspect {
		project := a.projectReport(r, probe)
		if r.workspace != nil {
			return bodyReply(r.command.Operation, protocol.ProjectCapabilityV2{Project: r.workspace.pin.WireIdentity(), CurrentPolicyRevision: r.workspace.policy.Revision, Capability: project})
		}
		return bodyReply(r.command.Operation, project)
	}
	if !compatible(r, probe) {
		return failure(r.command.Operation, "incompatible_delegate")
	}
	if r.command.Operation == protocol.Admit && !originOpen(r, probe) {
		return failure(r.command.Operation, "device_not_ready")
	}
	if r.command.Operation == protocol.ResumeExisting {
		if !existingOriginOpen(r, probe) {
			return failure(r.command.Operation, "device_not_ready")
		}
		return a.resume(ctx, r, owner)
	}
	return a.invokeReply(ctx, r, owner)
}

func (a *Adapter) inspect(ctx context.Context, r request, owner *controlOwner) (cliResponse, error) {
	inspection := r
	inspection.command.Operation = protocol.ContextInspect
	response, err := a.invoke(ctx, inspection, owner)
	if err != nil {
		return cliResponse{}, err
	}
	if response.exitCode != 0 || response.Error != "" || response.Failure != nil {
		return cliResponse{}, ErrConfiguration
	}
	return response, nil
}

func compatible(r request, response cliResponse) bool {
	c := response.Connector
	return c != nil && c.ContractVersion == 1 && protocol.NativeFeaturesCompatible(c.Features) && c.RootToken == r.project.RootToken && c.ProjectToken == r.project.ProjectToken && r.matchesWorkspace(c.WorkspaceConstraint)
}

func registeredOrigin(r request, response cliResponse) bool {
	c := response.Connector
	return c != nil && c.OriginRegistered != nil && *c.OriginRegistered && c.OriginBarrier != nil && c.OriginBarrier.GatewayID == string(r.config.GatewayID)
}

func originOpen(r request, response cliResponse) bool {
	c := response.Connector
	return existingOriginOpen(r, response) && c.OriginBarrier.Generation == r.task.Origin.AdmissionGeneration
}

// Existing recovery retains the task's original generation. A current open
// namespace gates execution without rewriting that immutable task receipt.
func existingOriginOpen(r request, response cliResponse) bool {
	return compatible(r, response) && registeredOrigin(r, response) && response.Connector.OriginBarrier.AdmissionOpen && wireIdentifier(response.Connector.OriginBarrier.Generation) && wireIdentifier(response.Connector.OriginBarrier.RecoveryID)
}

func (a *Adapter) invoke(ctx context.Context, r request, owner *controlOwner) (cliResponse, error) {
	call, err := r.invocation(ctx, owner)
	if err != nil {
		return cliResponse{}, err
	}
	call.directory = owner.temporary
	if r.workspace != nil && (r.command.Operation == protocol.Admit || r.command.Operation == protocol.ResumeExisting) {
		call.startGuard = r.startGuard
	}
	return a.run(ctx, call)
}

func (a *Adapter) invokeReply(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	response, err := a.invoke(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	// Exit 4 is a collection outcome, including diagnostic Error/Failure fields.
	// Only a fresh healthy guarded resolve can authorize its rejected projection.
	rejectedCollect := r.command.Operation == protocol.Collect && response.exitCode == 4
	if !rejectedCollect && (response.exitCode != 0 || response.Error != "" || response.Failure != nil) {
		if response.Failure != nil {
			candidate := protocol.Failure{Code: response.Failure.Code, Retryable: true}
			if candidate.Validate() == nil {
				return protocol.Reply{Operation: r.command.Operation, Error: &candidate}
			}
		}
		return failed(r.command.Operation, ErrPending)
	}
	if r.command.Operation == protocol.FenceAbsent && !r.rootTaskProof(response) {
		return failed(r.command.Operation, ErrEvidence)
	}
	if needsCanonicalRead(r.command.Operation, response) {
		return a.canonicalReply(ctx, r, owner, response)
	}
	return r.translate(response)
}

func (a *Adapter) canonicalReply(ctx context.Context, r request, owner *controlOwner, response cliResponse) protocol.Reply {
	verified, err := a.canonicalRead(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if r.command.Operation == protocol.Collect && response.exitCode == 4 && (verified.Publication != "rejected" || verified.Outcome == nil || verified.Outcome.Verdict != "rejected") {
		return failed(r.command.Operation, ErrEvidence)
	}
	// Only this successful guarded cancellation supplies a fresh stop receipt.
	// Passive resolve supplies immutable binding and canonical task evidence.
	if r.command.Operation == protocol.Cancel {
		if response.TaskID != r.task.TaskID || response.RootID == "" || response.RootID != verified.RootID {
			return failed(r.command.Operation, ErrEvidence)
		}
		verified.Stop = response.Stop
	}
	return r.translate(verified)
}

func needsCanonicalRead(op protocol.Operation, response cliResponse) bool {
	switch op {
	case protocol.Admit, protocol.ResumeExisting, protocol.Status, protocol.Collect, protocol.Cancel:
		return true
	case protocol.FenceAbsent:
		return response.Connector != nil && response.Connector.Resolution == "existing"
	case protocol.ContextInspect, protocol.Resolve, protocol.ResultChunk, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen, protocol.ResolveProject:
		return false
	default:
		return false
	}
}

func (a *Adapter) canonicalRead(ctx context.Context, r request, owner *controlOwner) (cliResponse, error) {
	passive := r
	passive.command.Operation = protocol.Resolve
	response, err := a.invoke(ctx, passive, owner)
	if err != nil {
		return cliResponse{}, err
	}
	if response.exitCode != 0 || response.Error != "" || response.Failure != nil {
		return cliResponse{}, ErrPending
	}
	if r.receipt(response) != nil {
		return cliResponse{}, ErrEvidence
	}
	return response, nil
}

func (a *Adapter) resume(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	passive := r
	passive.command.Operation = protocol.Resolve
	response, err := a.invoke(ctx, passive, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if response.Error != "" || response.exitCode != 0 || r.receipt(response) != nil {
		return failed(r.command.Operation, ErrEvidence)
	}
	if response.Connector == nil || response.Connector.Receipt == nil || response.Connector.Resolution != "existing" || !r.optionsAllowed(response.Connector.Receipt.ExecutionOptions) {
		return failure(r.command.Operation, "forbidden")
	}
	options := response.Connector.Receipt.ExecutionOptions
	r.startOptions = &options
	return a.invokeReply(ctx, r, owner)
}

func (a *Adapter) cancel(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	response, err := a.canonicalRead(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	if response.Connector.Resolution == "permanently_refused" {
		return r.translate(response)
	}
	if response.Connector.Resolution != "existing" {
		return failed(r.command.Operation, ErrPending)
	}
	if response.Connector.Receipt == nil {
		return failed(r.command.Operation, ErrEvidence)
	}
	if verified := r.translate(response); verified.Error != nil {
		return verified
	}
	r.task.SpecSHA256 = response.Connector.Receipt.SpecSHA256
	return a.invokeReply(ctx, r, owner)
}

func (a *Adapter) projectReport(r request, response cliResponse) protocol.ProjectCapability {
	result := protocol.ProjectCapability{Alias: r.project.Alias, Context: r.project.wireContext()}
	if c := response.Connector; c != nil {
		result.ContractVersion = c.ContractVersion
		result.Features = protocol.RecognizedNativeFeatures(c.Features)
		if c.OriginBarrier != nil {
			result.AdmissionGeneration = c.OriginBarrier.Generation
			result.AdmissionOpen = c.OriginBarrier.AdmissionOpen
		}
	}
	result.Ready = compatible(r, response) && result.AdmissionOpen && result.AdmissionGeneration != "" && a.Status().CleanupPending == 0
	if r.workspace != nil && !r.workspace.policy.Enabled {
		result.Ready = false
	}
	if !registeredOrigin(r, response) {
		result.Ready = false
	}
	for _, policy := range r.project.Providers {
		permissions := make([]string, len(policy.Permissions))
		for i, p := range policy.Permissions {
			permissions[i] = string(p)
		}
		result.Providers = append(result.Providers, protocol.ProviderCapability{Provider: policy.Provider, Models: append([]string(nil), policy.Models...), Efforts: append([]string(nil), policy.Efforts...), Permissions: permissions, MaxBudgetSeconds: policy.MaxBudgetSeconds, Authentication: "unknown"})
	}
	if result.Validate() != nil || (result.AdmissionGeneration != "" && !wireIdentifier(result.AdmissionGeneration)) {
		return protocol.ProjectCapability{Alias: r.project.Alias, Context: r.project.wireContext()}
	}
	return result
}

// Probe is an explicit dated public-CLI observation, never automatic migration.
func (a *Adapter) Probe(ctx context.Context) protocol.CapabilityReport {
	cfg := a.snapshot()
	report := protocol.CapabilityReport{ObservedAt: a.now()}
	ready := true
	for _, project := range cfg.Projects {
		command := protocol.Command{Operation: protocol.ContextInspect, Project: project.Alias}
		encoded, err := protocol.Encode(protocol.InspectRequest{GatewayID: string(cfg.GatewayID)}, protocol.MaxFrameBytes)
		if err != nil {
			ready = false
			continue
		}
		command.Body = encoded
		reply := a.execute(ctx, command, acceptance{generation: cfg.generation})
		var capability protocol.ProjectCapability
		if reply.Error != nil || protocol.DecodeStrict(reply.Body, &capability, protocol.MaxFrameBytes) != nil {
			capability = protocol.ProjectCapability{Alias: project.Alias, Context: project.wireContext()}
		}
		if !capability.Ready {
			ready = false
		}
		report.Projects = append(report.Projects, capability)
	}
	copyReport := cloneReport(report)
	a.mu.Lock()
	if a.config.generation == cfg.generation {
		a.report = copyReport
		a.observed = make(map[string]time.Time, len(report.Projects))
		for _, project := range report.Projects {
			a.observed[project.Alias] = report.ObservedAt
		}
		a.probed = ready
	}
	a.mu.Unlock()
	return report
}

func cloneReport(report protocol.CapabilityReport) protocol.CapabilityReport {
	data, err := protocol.Encode(report, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.CapabilityReport{ObservedAt: report.ObservedAt}
	}
	var result protocol.CapabilityReport
	if protocol.DecodeStrict(data, &result, protocol.MaxFrameBytes) != nil {
		return protocol.CapabilityReport{ObservedAt: report.ObservedAt}
	}
	return result
}

// Capabilities copies the dated cache; it never performs I/O or grants rights.
func (a *Adapter) Capabilities() protocol.CapabilityReport {
	a.mu.RLock()
	cached := a.report
	cfg := a.config
	a.mu.RUnlock()
	result := cloneReport(cached)
	if result.ObservedAt.IsZero() {
		result.ObservedAt = a.now()
		for _, p := range cfg.Projects {
			result.Projects = append(result.Projects, protocol.ProjectCapability{Alias: p.Alias, Context: p.wireContext()})
		}
	}
	if a.Status().CleanupPending != 0 {
		for i := range result.Projects {
			result.Projects[i].Ready = false
		}
	}
	return result
}

func detachedControl(owner context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(owner), duration)
}

func taskControl(operation protocol.Operation) bool {
	switch operation {
	case protocol.Resolve, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.Cancel, protocol.FenceAbsent:
		return true
	case protocol.Admit, protocol.ResumeExisting, protocol.ContextInspect, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen, protocol.ResolveProject:
		return false
	default:
		return false
	}
}

func (a *Adapter) executeTaskControl(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	switch r.command.Operation {
	case protocol.Resolve:
		return a.invokeReply(ctx, r, owner)
	case protocol.FenceAbsent:
		return a.resolveOrFence(ctx, r, owner)
	case protocol.Cancel:
		return a.cancel(ctx, r, owner)
	case protocol.Status, protocol.Collect, protocol.ResultChunk:
		response, err := a.canonicalRead(ctx, r, owner)
		if err != nil {
			return failed(r.command.Operation, err)
		}
		if response.Connector.Resolution != "existing" {
			return r.translate(response)
		}
		if response.Connector.Receipt == nil {
			return failed(r.command.Operation, ErrEvidence)
		}
		r.task.SpecSHA256 = response.Connector.Receipt.SpecSHA256
		return a.invokeReply(ctx, r, owner)
	case protocol.Admit, protocol.ResumeExisting, protocol.ContextInspect, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen, protocol.ResolveProject:
		return failed(r.command.Operation, ErrEvidence)
	default:
		return failed(r.command.Operation, ErrEvidence)
	}
}

// verifiedRoot validates the expected root without accessing a live project.
func (a *Adapter) verifiedRoot(ctx context.Context, r request, owner *controlOwner) (protocol.RootCapability, error) {
	probe := r
	probe.rootOnly = true
	response, err := a.inspect(ctx, probe, owner)
	if err != nil {
		return protocol.RootCapability{}, err
	}
	return r.rootReport(response)
}

func (a *Adapter) executeRootControl(ctx context.Context, r request, owner *controlOwner) protocol.Reply {
	report, err := a.verifiedRoot(ctx, r, owner)
	if err != nil {
		return failed(r.command.Operation, err)
	}
	a.observeRoot(r.config.generation, report)
	if r.command.Operation == protocol.ContextInspect {
		return bodyReply(r.command.Operation, report)
	}
	if r.command.Operation == protocol.OriginBarrier || r.command.Operation == protocol.OriginReopen {
		a.invalidateRootReadiness(r.config.generation, r.project.RootToken)
	}
	reply := a.invokeReply(ctx, r, owner)
	if reply.Error == nil && (r.command.Operation == protocol.OriginBarrier || r.command.Operation == protocol.OriginReopen) {
		var state protocol.OriginStateReport
		if protocol.DecodeStrict(reply.Body, &state, protocol.MaxFrameBytes) == nil && state.Validate() == nil {
			report.OriginRegistered, report.Origin = true, &state
			a.observeRoot(r.config.generation, report)
		}
	}
	return reply
}
