# Public integration contracts

Status: frozen target v1; these additions are not yet available in a released
Delegate installation. Gateway must refuse execution readiness without the
required version/features. No import of Delegate `internal/` packages or use of
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
| `prepare_dispatch` | Validate explicit device/project and immutable request; persist random handle; no launch |
| `dispatch_task` | Confirm the existing handle; no new identity, silent failover or offline work queue |
| `list_operations`, `resolve_operation`, `get_task_status` | Current-owner/current-grant observation; passive resolution cannot launch or fence |
| `recover_admission` | Explicit dispatch authorization; only existing matching prepared work |
| `collect_result`, `read_result_chunk` | Accepted descriptor, verified preview/range, length/digest and freshness |
| `cancel_task` | Stable cancellation ID; requested stop is not confirmed termination |

Schemas are strict and versioned. Model-supplied identity is not authentication.
Operation handles are not bearer capabilities. User principal is validated
`(issuer, subject)`; inventory, dispatch, read and cancellation scopes remain
separate and also require per-device/project grants.

## Delegate public boundary

The dedicated Delegate worktree implements these additive interfaces:

- `context inspect`: opaque root/project guards, contract version and features.
- `context enable-connector`: explicit per-root offline cutover; preserve sealed
  history and require incompatible legacy writers to reject the upgraded root.
- Guarded `dispatch --id`: frozen request and canonical origin/receipt.
- `resolve`: passive by default; explicit existing-only resume, absent refusal,
  and separate operator-only unattributed-partial recovery.
- Guarded `cancel --id`: preserve the existing cancellation owner and stop facts.
- Guarded `result read`: committed payload only, no arbitrary path/basename.
- `origin barrier`, `origin inventory`, `origin reopen`: admin-only recovery,
  generation checks and canonical membership/completeness receipts.

Origin fields are `gateway_id`, `admission_generation`, `operation_id`,
`principal_ref`, `gateway_request_sha256`. The Gateway request digest and
Delegate `spec_sha256` identify different bytes. Receipts also carry context,
task and brief identity. Recovery compares canonical persisted state.

Public task controls check the expected root/project/origin as applicable.
Ordinary existing CLI behavior remains when the new guards are not requested.
Connector invocation uses fixed argv and strict JSON/stdin, never shell assembly.
The existing admission/liveness/publication fields remain authoritative and
separate from the new connector projection.

The public projection includes canonical `execution_closure` (kind and exact
evidence-file SHA-256), or a typed `execution_closure_pending` reason. Failure
and busy observations carry no release proof. Accepted publication may precede
native closure; retrieving an accepted result does not release its reservation.
Receipt `execution_options` exposes requested selections, permission and exact
`budget_nanoseconds` for current connector-ceiling checks during existing-only
recovery. No brief, path, environment or raw error belongs in this projection.

Actual CLI context tokens stay connector-local. WSS context guards are
`ctx1_` plus SHA-256 of those tokens. The connector validates local CLI receipts
then normalizes their bindings; remote arguments never become local paths.

## WSS protocol

Required subprotocol: `delegate-gateway.v1`. Envelope fields: `version`, `type`,
`request_id`, `connection_generation`, optional `operation_id`, `ttl_ms`, `payload`.
Use tagged strict payloads, one reader and bounded writers; compression is off.

Operations: `context_inspect`, `admit`, `resolve`, `resume_existing`,
`fence_absent`, `status`, `collect`, `result_chunk`, `cancel`, `origin_barrier`,
`origin_inventory`, `origin_reopen`, and typed certificate renewal messages.
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

## Limits and errors

| Limit | Default |
| --- | --- |
| UTF-8 brief / encoded frame or HTTP body | 256 KiB / 1 MiB; validate both before possible-send |
| Result chunk | 64 KiB, full-payload verification before returning bytes |
| Outstanding operations | 2/device, 32 global; uncertainty retains reservations |
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
