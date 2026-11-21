# Public integration contracts

Status: Native-connect extension candidate, with negotiated WSS v1/v2 and
Native public contract version 1. Extension engineering gates, live acceptance
and final review remain pending; earlier MVP evidence does not cover it.
Gateway must refuse execution readiness without the required version/features. No import of Delegate `internal/` packages or use of
its private SSH server is allowed.

This candidate requires both `namespace-admission-v1` and
`namespace-mutation-lease-v1` on the selected Native root. Interface version 1
alone is insufficient. Upgrade with a compatible Delegate and an explicit
offline connector cutover before retrying; Gateway never enables a root or
selects another installation automatically. The same minimum applies to
historical task controls, without requiring the saved project directory to
remain present. Capability checks do not establish provider or cloud acceptance.

## MCP tools

| Tools | Required behavior |
| --- | --- |
| `list_devices`, `list_projects`, `get_capabilities` | Authorized paginated inventory and dated readiness; aliases only, no local paths |
| `list_workspaces` | Owned-device approved scopes plus Native automatic OS temporary scopes; no task or pin allocation |
| `list_directory`, `read_file`, `inspect_git` | Scope-relative, bounded live directory pages, exact requested byte ranges and structural Git metadata; both task dispatch and read access required |
| `list_models` | Explicit dated Native model/effort discovery with content-bound pagination; advisory, never an allowlist |
| `resolve_project` | Legacy durable alias compatibility; not needed for new scope-relative task preparation |
| `prepare_dispatch` | New flow: stable client request ID, exact device, scope-relative selection and immutable Native option intent; persist operation/task identities before dispatch; no launch |
| `prepare_continuation` | Prepare one successor from a saved predecessor operation on the explicit device; omitted selection/brief/options inherit; confirmation still uses `dispatch_task` |
| `dispatch_task` | Confirm the existing handle; no new identity, silent failover or offline work queue |
| `list_operations`, `resolve_operation`, `get_task_status` | Current-owner/current-grant observation; passive resolution cannot launch or fence |
| `recover_admission` | Explicit dispatch authorization; only existing matching prepared work |
| `collect_result`, `read_result_chunk` | Accepted descriptor, verified preview/range, length/digest and freshness; collection returns nonretryable `result_unavailable` for a fresh validated Native rejection |
| `cancel_task` | Stable cancellation ID; requested stop is not confirmed termination |

Schemas are strict and versioned. Model-supplied identity is not authentication.
Operation handles are not bearer capabilities. User principal is validated
`(issuer, subject)`; inventory, dispatch, read and cancellation scopes remain
separate. Legacy devices require per-device/project grants; self-enrolled devices
require their immutable owner and current enabled owner policy. Connector approvals
authorize local scopes, not providers, models, execution permission or task budget.
Native alone validates/defaults execution options; no cached catalog veto is allowed.

`list_workspaces` keeps approved workspace inventory available if optional live
temporary-scope discovery fails. It returns dated workspace-only metadata and a
closed `scope_discovery_error` code; missing temporary scopes are not evidence
that the device has none. It returns no failed discovery's data or source. Current
inventory authorization and the request deadline still apply. A successful live
temporary-scope response also rechecks file access and its original connection.

`get_capabilities` reports `task_read_allowed` and `task_cancel_allowed` for the
selected device/project. Each is the intersection of the verified token scopes
and current Registry authority (legacy grant or owner policy), even when the device is offline or has no
provider report. They are request-time authorization observations, independent
of provider authentication and execution readiness. Later controls recheck
authority; these fields cannot promise cleanup after expiry or revocation.

### Scope-relative preparation

The new `prepare_dispatch` shape uses `request_id`, `device_id`, `selection`
(`scope_id`, `relative_path`), `brief`, and `native_options`. Its provider is
explicit; model, effort, permission, budget, review target and timeout fields
remain omitted unless requested. The Gateway validates literal wire shape and
size; Native decides support and defaults. The legacy `project_alias` shape is
separate; mixed old/new fields, including explicit zero/null fields, are rejected.

The client retains the request ID before invocation. The Registry resolves that
key before live selection and ID allocation; identical replay returns the same
operation, changed input conflicts. Historical task controls use immutable saved
guards even after the project directory or approval disappears.

Preparation also checks that the captured identity fits both cancellation/fence
requests and their replies within the protected 16 KiB message budget. Oversize
returns permanent `resource_limit` before creating work. Earlier unsent drafts
retain their replay identity but must pass this check before first send. This
does not resolve already-sent work whose identity exceeds the control budget.

New-route admission requires Native's `origin-binding-v1`, execution-options and
project-hash capabilities. An absent binding cannot authorize a new path-based
admission or existing-only recovery. Missing capabilities fail explicitly;
there is no fallback to a legacy project alias. The candidate's final integrated
review and live acceptance have not been completed.

For a follow-up, call `prepare_continuation` with `device_id`, the saved
`predecessor_operation_id`, and a new stable `request_id`. Omit `selection` to
reuse the predecessor's captured route; an explicitly selected approval must
still match the same Native root, project and workspace guards. Omit `brief` to
inherit Native's exact saved bytes. Only budget, model, effort and output-silence
timeout can be overridden; `output_silence_timeout: "0"` disables that timeout.
Explicit null selection/brief is invalid. Native alone decides whether its saved
session is eligible for continuation. Retain the returned successor operation
and confirm it with `dispatch_task`. After uncertainty, reuse that same request
or operation; never replace it with an ordinary dispatch.

## Delegate public boundary

The dedicated Delegate worktree implements these additive interfaces:

- `context inspect`: opaque root/project guards, contract version and features.
- `context enable-connector`: explicit per-root offline cutover; preserve sealed
  history and require incompatible legacy writers to reject the upgraded root.
- `filesystem list|read|inspect|git|scopes --request FILE`: rooted Native filesystem
  observations, without initializing a task namespace.
- Scoped `models --expected-root --expected-workspace-file --relative-project`:
  explicit Native discovery with path custody through provider start and completion.
- Guarded `dispatch --id`: frozen request and canonical origin/receipt.
- Guarded `continue --task --id`: immutable predecessor guards, a fresh successor
  Origin, inherited Native context/options and a stable successor task identity.
- `resolve`: passive by default; explicit existing-only resume, absent refusal,
  and separate operator-only unattributed-partial recovery.
- Guarded `cancel --id`: preserve the existing cancellation owner and stop facts.
- Guarded `result read`: committed payload only, no arbitrary path/basename.
- `origin barrier`, `origin inventory`, `origin reopen`: admin-only recovery,
  generation checks and canonical membership/completeness receipts.

Origin fields are `gateway_id`, `admission_generation`, `operation_id`,
`principal_ref`, `gateway_request_sha256`, and optional opaque `binding`.
The Gateway request digest and
Delegate `spec_sha256` identify different bytes. Receipts also carry context,
task and brief identity. Recovery compares canonical persisted state.

### Compact intent and registry-loss recovery

The candidate's version-4 binding commits a closed request kind (`dispatch` or
`continuation`), immutable owner/device/root/project/operation/task identities,
the actual selected route, client request key, caller-input digest, and requested
brief presence/digest. Continuation additionally commits the predecessor's
operation, task, Native spec and request digest. Native stores this text as
opaque immutable Origin evidence; Gateway alone interprets its canonical format.
Historical version-2/version-3 request digests and absent-binding Origin bytes
remain unchanged. This executable capability does not add a root-wide migration.

The raw requested execution options stay in the retained Gateway request body;
they are not duplicated in Origin or reconstructed from Native's executed
options. Version-4 operation rows have no second options column authority.
After body disposal, the same request key can recover its original identities
and existing work can be observed, cancelled, fenced or explicitly recovered.
A bodyless row cannot authorize fresh admission. Native receipt/spec validation
still applies to existing-only recovery.

Canonical inventory restores both existing-task correlations and permanent
refusal tombstones. A refusal does not invent a Native spec, receipt, result or
execution closure. A present invalid/unknown/noncanonical binding, mismatched
outer identity or wrong immutable device owner rejects the entire import page;
progress and completeness do not advance. Recovery stays closed. Missing legacy
bindings retain their historical rules. Current scopes and credentials are
checked independently; an old binding never restores revoked authority.

Native inventory hashes retain the existing canonical bytes, order, paging and
completeness rules. Its scanner retains sorted IDs and only a bounded page of
decoded entries, and hashes each entry incrementally. Every page still scans
the full membership; there is no constant-I/O claim. An already-open reopen
retry validates the committed receipt without rescanning newly admitted tasks.

### Native control output

Guarded Native invocations use a 4 MiB JSON response envelope. Binding-present
controls project the same public response type onto identity, full canonical
Outcome, receipts, descriptors/ranges, closure, fresh stop and structured failure
fields. Unused auxiliary fields and the human recovery-command hint are omitted;
failure codes and exit status keep their meaning. Overflow fails explicitly,
without partial JSON or unverified result bytes. Ordinary and schedule response
limits are unchanged. The connector still applies its independent wire bound.
Native inventory bytes and membership hashes do not use this projection.

Public task controls check the expected root/project/origin as applicable.
Ordinary existing CLI behavior remains when the new guards are not requested.
Connector invocation uses fixed argv and strict JSON/stdin, never shell assembly.
The existing admission/liveness/publication fields remain authoritative and
separate from the new connector projection.

The public projection includes canonical `execution_closure` (kind and exact
evidence-file SHA-256), or a typed `execution_closure_pending` reason. Failure
and busy observations carry no release proof. Accepted publication may precede
native closure; retrieving an accepted result does not release its reservation.
Native receipt `execution_options` exposes requested selections, permission and exact
`budget_nanoseconds` without rounding historical intent during existing-only
recovery. Binding-present wire inventory omits these observed options; its
correlation comes from the binding commitment. Legacy wire receipts retain them.
These are Native facts, not a connector execution ceiling. No brief, path,
environment or raw error belongs in this projection.

Actual CLI context tokens stay connector-local. WSS context guards are
`ctx1_` plus SHA-256 of those tokens. The connector validates local CLI receipts
then normalizes their bindings; remote arguments never become local paths.

## WSS protocol

Negotiated subprotocols: `delegate-gateway.v1` and `delegate-gateway.v2`.
A session validates every frame against its negotiated version; v2 is not
accepted under v1. Native public-contract compatibility remains version 1,
independent of wire version. Envelope fields: `version`, `type`,
`request_id`, `connection_generation`, optional `operation_id`, `ttl_ms`, `payload`.
Use tagged strict payloads, one reader and bounded writers; compression is off.

Operations: `context_inspect`, `admit`, `resolve`, `resume_existing`,
`fence_absent`, `status`, `collect`, `result_chunk`, `cancel`, `origin_barrier`,
`origin_inventory`, `origin_reopen`, and typed certificate renewal messages.
Wire v2 adds `resolve_project`, `select_project`, `provider_models`,
`filesystem_scopes`, `list_directory`, `read_file`, `inspect_file`, `inspect_git`
and root-addressed controls; v1 rejects those additions. V2 capability reports carry bounded root/workspace inventory and dated legacy pin
budget. New executable capabilities are individually negotiated; missing filesystem,
scoped-model, Native-option or historical-hash support fails with an upgrade error. Targeted project inspection carries one immutable pin and a
current policy revision, never an expanded periodic project list.
Legacy v1 and alias-based v2 replies retain their original error vocabulary and
omit newer stage fields. An error unknown to those readers uses their existing
`pending` response; it never proves that a task was absent or closed. New routed
and metadata operations retain their supported safe Native error codes/stages.
Recovery-only credentials cannot admit, resume or reopen. Admin operations are
never MCP-callable. Superseded generations and stale completeness receipts fail
closed.

Within its protected control owner, `fence_absent` first performs a guarded
passive lookup. Complete matching existing evidence returns without acquiring
Delegate's partial-preparation refusal exclusion. Validated absence triggers
the independently guarded native refusal fence. The exact native partial
`unresolved` response may also select that fence, but supplies no identity,
spec, refusal or closure evidence itself. Malformed responses, mismatched
receipts and ordinary read errors do not trigger a fallback fence.
That partial fallback also requires a successful root-only inspection of the
expected root and both required features before sending any refusal mutation.
The inspection does not require the saved project path, and its response never
replaces the original task guards.

`cancel` validates the canonical frozen receipt before issuing guarded native
cancellation with the stable cancellation ID. A post-cancel canonical read and
matching stop evidence remain required. Running workers retain their execution
ownership while receiving stop requests; a refusal fence is not a prerequisite
for stopping complete existing work. All sequential native controls retain the
same protected permit through actual Wait and cleanup.

## Owner enrollment and project pins

The optional public descriptor at `/.well-known/delegation-gateway` advertises
configured HTTPS issuer/resource/enrollment URLs, the same-host device WSS URL,
device CA and supported wires. `/v1/self/enroll` requires verified device-enroll
scope plus current Registry eligibility; `/v1/self/devices/revoke` requires
device-manage scope and exact ownership. Enrollment request replay is bound to
the first owner and CSR/key/selection, and replacement requires the expected
credential generation. Neither route exposes private administration.
See [public DTOs](../internal/selfservice/contract/types.go) and
[Registry authorization](../internal/registry/ownership.go).

The default Native-owned embedded service uses OAuth device login (including
headless approval) or an explicit private one-device enrollment token. Those
operator flows and their lifecycle limits are maintained in
[Native connect](native-connect.md); the standalone legacy connector is not the
default installation requirement.

`resolve_project` requires a saved 32-lowercase-hex request ID, explicit device,
workspace ID and clean existing relative directory (`.` is allowed). Absolute
paths, traversal and remote filesystem creation are excluded. Native checks
actual ancestry and symlinks. Its first durable pin is replay identity, not
execution permission. Changed selector replay conflicts; removed/replaced
paths never silently replace a pin. Schema 9 stores the Gateway correlation
and routes by reference to that pin; local paths/tokens remain with Native.
Fresh targeted inspection rechecks that exact identity and current policy.
See [wire validation](../internal/protocol/workspace.go),
[resolution storage](../internal/registry/project_resolution.go) and
[local pin/Start ownership](../internal/connector/workspace_contract.go).

## Limits and errors

| Limit | Default |
| --- | --- |
| UTF-8 brief / encoded frame or HTTP body | 256 KiB / 1 MiB; validate both before possible-send |
| Workspace inventory / retained local project pins | 100 workspaces; 1,024 pins including tombstones, also bounded to 4 MiB encoded pin data; no eviction |
| Gateway durable resolution requests | 1,024/device, including pending requests; a capacity observation reserves no slot |
| Result chunk | 64 KiB, full-payload verification before returning bytes |
| Outstanding legacy alias operations | 2/device, 32 global; uncertainty retains reservations; new scope-relative operations use Native execution admission |
| Gateway-routed ordinary CLI controls / reserved cancellation-fence controls | Outer ceilings: 32 / 8 globally, held through actual Wait and cleanup |
| Whole-payload scan consumers | Every task control, including admit, resolve, resume, status, collect, cancel and result reads: 1/device, 4 global; ordinary controls may use 3, one slot is reserved for cancel/fence |
| Connector acceptance queue TTL / default scan deadline | 30 seconds / 30 seconds |
| Draft expiry / correlation retention | 15 minutes / indefinite for possibly-sent identities |

The scan ceiling is tighter than the outer control ceiling: at most three
ordinary task controls run fleet-wide. Cancel/fence uses a separate fixed one-slot global scan pool; ordinary work
cannot borrow it, and cancellation does not borrow the three ordinary slots. A
busy device scan returns `resource_limit` without starting or queuing that call.
This reports resource-pending behavior using the existing wire error enum.
No control preempts an accepted CLI. Context/origin controls count toward outer CLI ceilings but do not read
accepted payloads or sealed raw manifests. Origin inventory still traverses
canonical history and preparation/refusal metadata; it has no constant-I/O claim. Routing permits persist across timeout, disconnect and Gateway
restart; only a validated settled/not-claimed completion or complete same-owner
fenced reconciliation releases them. A changed connector process with outstanding
permits requires protected local-admin CLI-only drain attestation. That
attestation never releases Delegate task reservations or restores authority.
The fleet ceilings cover Gateway-routed CLI controls. Locally initiated connector
startup metadata probes and operator CLI/SSH/TUI calls remain under their local
owners and are outside those fleet counts. Startup probes use the connector
local limits and finite context; they are never periodic execution work.
The routing contracts are implemented; integrated process and live acceptance
remain separate gates. See [recovery limits](recovery.md): uncertain accepted
calls retain capacity and may exhaust an entire operation class.

TTL is not a task-completion deadline. Subprocess capacity stays owned through
`Wait` and cleanup. Outer HTTP/client deadlines must accommodate inner deadlines.
Large-result verification may time out repeatedly; return no unverified bytes.
Partial refusal recovery can run three sequential native controls: passive
lookup, root inspection and refusal. A caller deadline bounds the sequence and
each control uses its remaining time. Without a caller deadline, the sequence
can consume up to three configured native control timeouts.

Return bounded typed errors, never native error strings or paths. OAuth HTTP
challenges and tool authentication metadata remain protocol fields outside the
application error object. Unsupported Delegate features mean not ready, never a
private-protocol fallback.

Operational error classification uses only a qualified sole cause. A known
timeout, invalid-input, size-limit or public policy error joined with an
independent operational failure becomes `internal_error`. Actual request
validation, token expiry and context cancellation are checked independently at
the tool boundary; they keep their priority without trusting mixed error graphs.
Keep a retained operation or resolution request ID after uncertainty; do not
replace it because a response was lost.
