package connector

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// The owned test binary acts as a real public-CLI process before testing parses
// argv. It never launches a model, uses a provider account or reads Delegate state.
func TestMain(m *testing.M) {
	if os.Getenv("GATEWAY_CONNECTOR_HELPER") == "1" {
		os.Exit(helper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

type (
	helperState struct {
		Block               string
		Mode                string
		Provider            string
		Permission          string
		Budget              int64
		NativeModel         bool
		Closure             bool
		Closed              bool
		Disabled            bool
		Features            []string
		Brief               string
		OriginGeneration    string
		LiveProjectMismatch bool
		ReceiptFault        string
		Absent              bool
		Partial             bool
		LiveOwner           bool
		ProbeFault          string
		ContextFault        string
		Refused             bool
		CancelTaskFault     string
		CancelRootFault     string
		ProjectToken        string
		Publication         string
		OutcomeFault        string
		CollectExit         int
		CollectFailure      string
		CollectMode         string
		AfterCollect        *helperState
	}
	helperCall struct {
		Command                 string
		Args                    []string
		Directory               string
		DelegateRootEnvironment string
		PWDEnvironment          string
		BriefMode               uint32
		OriginMode              uint32
		ExpectedOrigin          protocol.Origin
	}
)

func helper(args []string) int {
	flags, command, task, action := helperArguments(args)
	root := flags["root"]
	state, stateCode := readHelperState(root)
	if stateCode != 0 {
		return stateCode
	}
	if command != "context" && command != "dispatch" && flags["cwd"] != "" {
		return 93
	}
	if code := recordHelperCall(root, flags, command, args); code != 0 {
		return code
	}
	if command == state.Block {
		if code := waitHelper(root, task); code != 0 {
			return code
		}
	}
	response := helperResponse(flags, command, task, action, state)
	mode := state.Mode
	if command == "collect" && state.CollectMode != "" {
		mode = state.CollectMode
	}
	if mode == "unknown" {
		response["unrecognized_canary"] = "PRIVATE-CANARY"
	}
	exitCode := helperControlExit(flags, command, state, response)
	if emitCode := emitHelperResponse(response, mode); emitCode != 0 {
		return emitCode
	}
	if advanceCode := advanceHelperCollection(root, command, state.AfterCollect); advanceCode != 0 {
		return advanceCode
	}
	return exitCode
}

func advanceHelperCollection(root, command string, next *helperState) int {
	if command != "collect" || next == nil {
		return 0
	}
	data, err := json.Marshal(next)
	if err != nil {
		return 98
	}
	if err = os.WriteFile(filepath.Join(root, "helper-state.json"), data, 0o600); err != nil {
		return 99
	}
	return 0
}

// Native unsuccessful connector envelopes scrub attestations. Incomplete passive
// preparation has no error string but is still exit 3, never successful proof.
func helperControlExit(flags map[string]string, command string, state helperState, response map[string]any) int {
	if command == "context" {
		return helperContextExit(state.ContextFault, response)
	}
	if command == "collect" {
		return helperCollectionExit(state, response)
	}
	if command != "resolve" {
		return 0
	}
	fence := flags["fence-if-absent"] == "true"
	code := 0
	if state.LiveOwner && fence {
		response["error"] = "PRIVATE-CANARY owner busy"
		code = 3
	} else if state.Partial && !fence {
		code = 3
	} else if state.Mode == "passive-error" && !fence {
		response["error"] = "PRIVATE-CANARY read failure"
		code = 1
	}
	if code != 0 {
		connector, ok := response["connector"].(map[string]any)
		if !ok {
			return 98
		}
		connector["resolution"] = "unresolved"
		for _, field := range []string{"features", "root_token", "project_token", "execution_closure", "execution_closure_pending"} {
			delete(connector, field)
		}
		if state.Partial && !fence {
			code = helperPartialFault(state.ProbeFault, response, connector, code)
		}
	}
	return code
}

func helperCollectionExit(state helperState, response map[string]any) int {
	if state.CollectExit != 0 {
		response["error"] = "PRIVATE-CANARY rejected diagnostic"
		if state.CollectFailure != "" {
			response["failure"] = map[string]string{"code": state.CollectFailure, "stage": "collect", "next_action": "PRIVATE-CANARY"}
		}
	}
	return state.CollectExit
}

func helperContextExit(fault string, response map[string]any) int {
	switch fault {
	case "failed":
		response["error"] = "PRIVATE-CANARY inspect failure"
		return 1
	case "busy":
		response["error"] = "PRIVATE-CANARY lock busy"
		return 3
	case "failure":
		response["failure"] = map[string]string{"code": "pending"}
	}
	return 0
}

func helperPartialFault(fault string, response, connector map[string]any, code int) int {
	switch fault {
	case "receipt":
		connector["receipt"] = map[string]any{"spec_sha256": strings.Repeat("f", 64), "origin": map[string]string{"operation_id": "poison-origin"}}
	case "error":
		response["error"] = "PRIVATE-CANARY conflict"
	case "failure":
		response["failure"] = map[string]string{"code": "pending"}
	case "task":
		response["task_id"] = strings.Repeat("9", 32)
	case "contract":
		connector["contract_version"] = 2
	case "exit":
		return 1
	}
	return code
}

func readHelperState(root string) (helperState, int) {
	data, readErr := os.ReadFile(filepath.Join(root, "helper-state.json"))
	if readErr != nil {
		return helperState{}, 91
	}
	var state helperState
	if json.Unmarshal(data, &state) != nil {
		return helperState{}, 92
	}
	return state, 0
}

func recordHelperCall(root string, flags map[string]string, command string, args []string) int {
	call := helperCall{Command: command, Args: args}
	directory, directoryErr := os.Getwd()
	if directoryErr != nil {
		return 94
	}
	call.Directory = directory
	call.DelegateRootEnvironment = os.Getenv("DELEGATE_ROOT")
	call.PWDEnvironment = os.Getenv("PWD")
	for flag, target := range map[string]*uint32{"brief": &call.BriefMode, "origin": &call.OriginMode, "expected-origin": &call.OriginMode} {
		if path := flags[flag]; path != "" {
			info, statErr := os.Stat(path)
			if statErr != nil {
				return 94
			}
			*target = uint32(info.Mode().Perm())
			if flag != "brief" {
				data, readErr := os.ReadFile(path)
				if readErr != nil || json.Unmarshal(data, &call.ExpectedOrigin) != nil {
					return 94
				}
			}
		}
	}
	if appendErr := appendHelperCall(root, call); appendErr != nil {
		return 95
	}
	return 0
}

func waitHelper(root, task string) int {
	if task == "" {
		task = strconv.Itoa(os.Getpid())
	}
	if writeErr := os.WriteFile(filepath.Join(root, "started-"+task), []byte("started"), 0o600); writeErr != nil {
		return 96
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, statErr := os.Stat(filepath.Join(root, "release")); statErr == nil {
			return 0
		}
		if time.Now().After(deadline) {
			return 97
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func emitHelperResponse(response map[string]any, mode string) int {
	encoded, encodeErr := json.Marshal(response)
	if encodeErr != nil {
		return 98
	}
	if _, writeErr := os.Stdout.Write(encoded); writeErr != nil {
		return 99
	}
	if mode == "stdout" {
		if _, writeErr := os.Stdout.Write([]byte(strings.Repeat("x", MaxStdoutBytes+1))); writeErr != nil {
			return 99
		}
	}
	if mode == "stderr" {
		if _, writeErr := os.Stderr.Write([]byte(strings.Repeat("PRIVATE-CANARY", MaxStderrBytes))); writeErr != nil {
			return 99
		}
	}
	return 0
}

func appendHelperCall(root string, call helperCall) error {
	data, err := json.Marshal(call)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(root, "calls.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func helperArguments(args []string) (map[string]string, string, string, string) {
	flags := make(map[string]string)
	if len(args) == 0 {
		return flags, "", "", ""
	}
	command := args[0]
	task, action := "", ""
	index := 1
	if command == "context" || command == "origin" || command == "result" {
		if index < len(args) {
			action = args[index]
			index++
		}
	}
	if index < len(args) && !strings.HasPrefix(args[index], "--") {
		task = args[index]
		index++
	}
	for index < len(args) {
		name := strings.TrimPrefix(args[index], "--")
		index++
		if name == "json" || name == "resume-admission" || name == "fence-if-absent" || name == "include-workspace-constraint" {
			flags[name] = "true"
			continue
		}
		if index < len(args) {
			flags[name] = args[index]
			index++
		}
	}
	if command == "dispatch" {
		task = flags["id"]
	}
	return flags, command, task, action
}

func helperResponse(flags map[string]string, command, task, action string, state helperState) map[string]any {
	connector := helperConnectorHeader(flags, state)
	response := map[string]any{"schema_version": 1, "command": command, "root_id": "fixture-root-a", "admission": "unknown", "liveness": "undetermined", "publication": "unknown", "connector": connector}
	if command == "context" {
		helperContextResponse(flags, state, response, connector)
		return response
	}
	if command == "origin" {
		helperOriginResponse(flags, action, connector)
		return response
	}
	response["task_id"] = task
	response["admission"] = "admitted"
	response["liveness"] = "ended"
	response["publication"] = "pending"
	connector["resolution"] = "existing"
	if helperTaskPresence(flags, state, response, connector) {
		return response
	}
	if !helperReceipt(flags, task, state, response, connector) {
		return response
	}
	helperOutcome(task, state, response)

	if command == "dispatch" {
		response["task_record"] = "created"
		delete(connector, "resolution")
	}
	if flags["resume-admission"] == "true" {
		delete(connector, "receipt")
	}
	if flags["fence-if-absent"] == "true" {
		delete(connector, "receipt")
	}
	if command == "cancel" {
		response["stop"] = helperStop(flags["id"], state)
		helperCancelIdentityFault(response, flags["id"], "task_id", state.CancelTaskFault)
		helperCancelIdentityFault(response, flags["id"], "root_id", state.CancelRootFault)
		delete(response, "connector")
	}
	if command == "status" || command == "collect" {
		delete(response, "connector")
	}
	if command == "result" && action == "read" {
		helperRange(response, connector, flags, state)
	}
	return response
}

func helperCancelIdentityFault(response map[string]any, id, field, fault string) {
	if fault == "" {
		return
	}
	response["stop"] = helperStop(id, helperState{Closure: true})
	if fault == "missing" {
		delete(response, field)
	} else {
		response[field] = strings.Repeat("9", 32)
	}
}

func helperStop(id string, state helperState) map[string]any {
	if state.LiveOwner && !state.Closure {
		return map[string]any{"request_id": id, "requested": true, "matched": true, "attempted": true, "in_flight": true, "observed_state": "running", "terminated": false}
	}
	return map[string]any{"request_id": id, "requested": true, "matched": true, "attempted": true, "in_flight": false, "observed_state": "closed", "terminated": true, "message": "PRIVATE-CANARY"}
}

func helperOriginResponse(flags map[string]string, action string, connector map[string]any) {
	switch action {
	case "barrier", "reopen":
		connector["origin_barrier"] = map[string]any{"gateway_id": flags["gateway-id"], "recovery_id": flags["recovery-id"], "generation": flags["generation"], "admission_open": action == "reopen"}
	case "inventory":
		connector["inventory"] = map[string]any{"entries": []any{}, "complete": true, "membership_sha256": strings.Repeat("e", 64), "completeness_receipt": strings.Repeat("f", 64)}
	}
}

func helperContextResponse(flags map[string]string, state helperState, response, connector map[string]any) {
	if flags["cwd"] != "" {
		info, statErr := os.Stat(flags["cwd"])
		if statErr != nil || !info.IsDir() {
			response["error"] = "PRIVATE-CANARY missing project"
			return
		}
		if state.LiveProjectMismatch {
			connector["project_token"] = "replacement-project-PRIVATE-CANARY"
		}
	} else if flags["expected-workspace"] == "" {
		delete(connector, "project_token")
		if state.ContextFault == "project" {
			connector["project_token"] = "unexpected-project"
		}
	}
	connector["origin_registered"] = true
	connector["origin_barrier"] = map[string]any{"gateway_id": "gateway-one", "recovery_id": "recovery-one", "generation": helperOriginGeneration(state), "admission_open": !state.Closed}
}

func helperTaskPresence(flags map[string]string, state helperState, response, connector map[string]any) bool {
	if !state.Partial && !state.Absent && !state.Refused {
		return false
	}
	if state.Partial && flags["fence-if-absent"] != "true" {
		connector["resolution"] = "unresolved"
		response["admission"] = "unknown"
		response["liveness"] = "undetermined"
		response["publication"] = "unknown"
		return true
	}
	connector["resolution"] = "absent"
	if flags["fence-if-absent"] == "true" || state.Refused {
		connector["resolution"] = "permanently_refused"
	}
	response["admission"] = "unknown"
	response["liveness"] = "undetermined"
	response["publication"] = "unknown"
	return true
}

func helperReceipt(flags map[string]string, task string, state helperState, response, connector map[string]any) bool {
	originFile := flags["expected-origin"]
	if originFile == "" {
		originFile = flags["origin"]
	}
	originData, err := os.ReadFile(originFile)
	if err != nil {
		response["error"] = "PRIVATE-CANARY"
		return false
	}
	var origin map[string]any
	if json.Unmarshal(originData, &origin) != nil {
		response["error"] = "PRIVATE-CANARY"
		return false
	}
	model := map[string]string{"kind": "native_default"}
	if !state.NativeModel {
		model = map[string]string{"kind": "explicit", "value": "model-safe"}
	}
	options := map[string]any{"provider": state.Provider, "permission": state.Permission, "budget_nanoseconds": state.Budget, "model": model, "effort": map[string]string{"kind": "native_default"}}
	connector["receipt"] = map[string]any{"root_token": strings.Repeat("a", 64), "project_token": "local-project-token-PRIVATE-CANARY", "task_id": task, "origin": origin, "spec_sha256": strings.Repeat("c", 64), "brief_sha256": helperHash(state.Brief), "execution_options": options}
	receipt, ok := connector["receipt"].(map[string]any)
	if !ok {
		return false
	}
	helperAttachWorkspace(flags, receipt)
	switch state.ReceiptFault {
	case "root":
		receipt["root_token"] = strings.Repeat("f", 64)
	case "project":
		receipt["project_token"] = "different-project"
	case "origin":
		origin["operation_id"] = "different-operation"
	case "spec":
		receipt["spec_sha256"] = strings.Repeat("f", 64)
	case "feature":
		connector["features"] = []string{}
	case "liveness":
		response["liveness"] = "invalid-observation"
	case "workspace":
		receipt["workspace_constraint"] = map[string]string{"token": "unexpected-workspace", "relative_project": "."}
	}
	if state.Closure {
		connector["execution_closure"] = map[string]string{"kind": "registered-native", "reference_sha256": strings.Repeat("d", 64)}
	} else {
		connector["execution_closure_pending"] = "closure_unproven"
		if state.LiveOwner {
			connector["execution_closure_pending"] = "owner_busy"
			response["liveness"] = "running"
		}
	}
	return true
}

func helperOutcome(task string, state helperState, response map[string]any) {
	if state.Publication == "" {
		return
	}
	response["publication"] = state.Publication
	if state.OutcomeFault == "missing" {
		return
	}
	basename := "publish.reject"
	if state.Publication == "committed" {
		basename = "result.txt"
	}
	outcome := map[string]any{
		"schema_version": 1, "task_id": task, "spec_sha256": strings.Repeat("c", 64), "verdict": state.Publication,
		"payload":     map[string]any{"basename": basename, "sha256": helperHash("PRIVATE-CANARY"), "length": len("PRIVATE-CANARY")},
		"diagnostics": []map[string]string{{"code": "PRIVATE-CANARY", "message": "PRIVATE-CANARY"}},
	}
	switch state.OutcomeFault {
	case "schema":
		outcome["schema_version"] = 2
	case "task":
		outcome["task_id"] = strings.Repeat("9", 32)
	case "spec":
		outcome["spec_sha256"] = strings.Repeat("f", 64)
	}
	response["outcome"] = outcome
}

func helperRange(response, connector map[string]any, flags map[string]string, state helperState) {
	data, err := os.ReadFile(flags["expected-descriptor"])
	if err != nil {
		response["error"] = "PRIVATE-CANARY"
		return
	}
	var descriptor map[string]any
	if json.Unmarshal(data, &descriptor) != nil {
		response["error"] = "PRIVATE-CANARY"
		return
	}
	result := []byte("accepted result")
	connector["result_range"] = map[string]any{"descriptor": descriptor, "offset": 0, "data_base64": base64.StdEncoding.EncodeToString(result), "next_offset": len(result), "eof": true}
	response["publication"] = "committed"
	if state.Mode == "range" {
		connector["result_range"] = map[string]any{"descriptor": descriptor, "offset": 0, "data_base64": base64.StdEncoding.EncodeToString(result), "next_offset": 999, "eof": true}
	}
}

func helperHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func helperOriginGeneration(state helperState) string {
	if state.OriginGeneration != "" {
		return state.OriginGeneration
	}
	return "origin-one"
}

func helperConnectorHeader(flags map[string]string, state helperState) map[string]any {
	features := []string{"namespace-admission-v1", "namespace-mutation-lease-v1"}
	if state.Features != nil {
		features = state.Features
	}
	if state.Disabled {
		features = []string{}
	}
	connector := map[string]any{"contract_version": 1, "features": features, "root_token": strings.Repeat("a", 64), "project_token": "local-project-token-PRIVATE-CANARY"}
	if state.ProjectToken != "" {
		connector["project_token"] = state.ProjectToken
	}
	if state.ReceiptFault == "root-header" {
		connector["root_token"] = strings.Repeat("f", 64)
	}
	helperAttachWorkspace(flags, connector)
	return connector
}

func helperAttachWorkspace(flags map[string]string, target map[string]any) {
	if flags["expected-workspace"] != "" {
		target["workspace_constraint"] = map[string]string{"token": flags["expected-workspace"], "relative_project": flags["relative-project"]}
	}
}
