# Root initialization and recovery

The Native-connect extension adds owned-device and workspace-pin state to the
existing root initialization, fleet restore and private task controls. Its full
gates, live flows and final integrated review remain pending. Historical MVP
acceptance does not validate the new paths.
The current acceptance status is recorded in [verification](verification.md).
Use these controls to preserve Registry and Delegate evidence through recovery.

## Identity and root ownership

`gateway init --database ABS` creates a new private database and generates its
Gateway identity. `gateway identity --database ABS` reads that identity while the
instance is stopped. Serving requires existing, complete storage and the matching
configured identity. It never initializes missing storage automatically.

A project registration contains `device_id`, `project_alias`, `root_guard` and
`project_guard`. Guards are the connector's normalized context identifiers;
local paths and raw Delegate context tokens stay on the device. An operator
cannot supply an admission generation. Registry owns eligibility once per
bound device/root, shared by its aliases.

## Native-owned profiles, policy and retained project identity

The normal Native-connect path embeds the client in Native's own user service.
OAuth/headless login, private browserless enrollment tokens, workspace approval
and service commands are maintained in [Native connect](native-connect.md).
Gateway does not take over that service or Native task supervision. Disconnect
and device revocation are not cancellation or execution-closure proofs.

A self-enrolled device has one immutable Registry owner and uses that owner's
current enabled policy rather than copied per-project grants. Owner disablement
preserves ownership/history while denying current authority. Legacy devices
continue to require explicit grants; login, migration or restore never assigns
a legacy device to the next user. Self-enrollment replay retains the original
request/CSR identity; device replacement needs exact owner and generation checks.
See [ownership](../internal/registry/ownership.go) and
[self-enrollment](../internal/registry/self_enrollment.go).

Wire-v2 project handles reference the first accepted workspace-relative pin.
Retain the original resolution request ID after lost replies, directory
replacement or policy changes. A changed selector conflicts; a completed replay
is identity, not current execution permission. All retained Gateway resolution
requests, including unsuccessful or pending attempts, count toward the
1,024/device cap. Retrying the same request uses its existing slot; no automatic
compaction or reset is provided. Local pins, including tombstones, also have a
1,024-record and four-MiB encoded-data cap. Nothing evicts old identity to make
room. Workspace metadata advertises only dated local pin-budget usage, rather
than the separate Gateway request count; it reserves no slot.
See [resolution storage](../internal/registry/project_resolution.go) and
[wire bounds](../internal/protocol/workspace.go).

First-use owned-root initialization uses the existing durable phases through an
exact device/root/credential/connection-bound port, with current owner policy
rechecked inside every transaction. It can initialize an eligible empty root
before a project exists; it cannot bypass an active fleet restore, import task
history, grant private administration or waive routing coverage. A nonempty
namespace still needs explicit supported restore. See
[owned-root authority](../internal/registry/owned_root.go) and
[allowed routed commands](../internal/registry/owned_root_routing.go).

Workspace removal disables new resolution/admission/resume without erasing
saved task bindings. Authorized passive controls retain the frozen identity;
current principal/device authority is still mandatory. Refresh capabilities for
one saved handle rather than replaying a stale project list. Neither policy
revision nor fresh metadata can rewrite an old task or release uncertainty.

## Stale administrative socket after an unclean exit

The admin listener refuses a pre-existing socket path, including a stale socket
left by a crash. Recovery is an explicit operator action. Hold exclusive leases
on the state directory's `gateway.lock` and the socket directory's `.admin.lock`;
verify the private socket is owned by the service account, no listener accepts
connections, and its filesystem identity stays unchanged. Preserve the stale
socket under a separate path before starting Gateway with the same database,
identity and certificate configuration. Keep the stable lease files in place.

Acquiring new listener ownership does not establish the old process's join or
the closure of any Delegate task. Retain uncertain task reservations and their
original identities for recovery through the connected Delegate namespace.

## Private root controls

Use the private Unix socket and an owned regular 0600 input file:

```sh
gateway admin --socket "$admin_socket" --action initialize-root --input-file "$root_input"
gateway admin --socket "$admin_socket" --action root-progress --input-file "$root_input"
```

`root_input` contains the same four device/project/context fields as registration.
`initialize-root` advances one durable phase per call. Repeat the same input
until `stage` is `ready`: barrier, complete inventory, approval, then reopen.
Every retry uses Registry's persisted session and generation. The final phase
explicitly verifies the root namespace again. Project readiness is separate:
legacy projects require explicit refresh, and wire-v2 handles use fresh targeted
inspection. Root-only evidence cannot promote a missing workspace to ready. Registry readiness, dated connector capabilities and provider
authentication are separate facts; capability publication can lag a completed
phase.

An unexpected existing namespace returns conflict. It is never adopted as an
empty root. Protected `abandon-root` takes an input file containing the exact
`recovery_id`. It retains evidence and reservations and requires explicit fleet
restore; it cannot reset a completed initialization or abandon one whose reopen
receipt was already recorded. Use it only when that recovery is intended.

A second alias on the same open root reuses its eligibility. Registration or
reconnection cannot open a pending root. `list_devices`, `list_projects` and
`get_capabilities` report execution readiness only when current Registry
eligibility matches the authenticated connector and advertised context/generation.
A dated `delegate_ready` capability alone does not grant admission.

## Private fleet restore controls

For a backup restore, stop Gateway and restore a consistent SQLite backup.
Keep its original Gateway identity and device-CA custody. While Gateway is
stopped, run the offline maintenance commands before starting listeners.

```sh
gateway migrate --database "$database"
gateway begin-recovery --database "$database" --recovery-id "$recovery_id"
gateway serve --config "$gateway_config"
```

Migration upgrades schema 6, 7 or 8 to schema 9 atomically and preserves the
existing identity, grants, task correlations, observations and routing evidence.
A valid schema-9 database is an idempotent success. Ownership tables do not adopt
legacy devices, and project-resolution tables do not infer missing pins.
See [migration source](../internal/registry/migration.go). The offline
recovery command commits credential/grant fencing under the existing instance
lease. Start serving after both commands succeed. Use a fresh recovery ID for
each distinct restore event and reuse that ID for retries of the same intent.
This ordering is required for a restored backup because a snapshot cannot
identify work admitted after it was taken.

Every action uses `gateway admin --socket ABS --action ACTION --input-file ABS`.
Input files require regular owned 0600 storage. Keep the same `recovery_id`
through retries. Gateway generates and persists the credential epoch and target
admission generations.

| Action | Input fields | Effect |
| --- | --- | --- |
| `begin-recovery` | `recovery_id` | Begin or recover the original active restore attempt |
| `register-recovery-root` | `recovery_id`, `device_id`, `root_guard` | Add an explicitly identified prior root before sealing |
| `register-routing-recovery-roster` | `recovery_id`, `device_ids` | Record the operator's complete prior device roster |
| `seal-recovery` | `recovery_id`, `expected_destinations` | Verify and seal the complete root count |
| `recovery-progress` | optional `recovery_id`, optional `after`, required `limit` | Read dated progress and mapping debt |
| `advance-recovery` | `recovery_id`, `device_id`, `root_guard`, `project_alias` | Perform one phase on the selected root |
| `finish-recovery` | `recovery_id` | Recheck the whole recovery and reopen Gateway admission |

The prior-device roster requires an explicit array, including `[]` for an empty
fleet. Supply it from retained operator evidence. The current snapshot can omit
devices that existed before restore. Root and routing rosters therefore have
separate completeness checks.

Re-enroll and connect the complete declared fleet with recovery-only credentials.
Establish routing census coverage for every device first. A changed or unknown
prior connector boot leaves sticky routing debt, including when the snapshot
contains zero active routing records. Resolve that debt through the protected
CLI-ownership attestation below. Gateway-routed CLI controls wait for complete
fleet coverage, including project refresh, barriers, inventory, resolve and
cancellation.

Then advance each root through its durable barrier and canonical inventory. Progress can report
`needs_mapping` or `needs_regular_credential`. Resolve or drain retained tasks,
complete the routing census and obtain regular credentials. Reconnection makes
older route proofs stale, so resolve affected contexts again on the new
connection before approval. Continue until each root has a verified reopen.
Call `finish-recovery` explicitly after the complete roster is ready.

A root's `ready` stage describes that destination. The enclosing recovery
remains active until the final whole-recovery check succeeds. Route changes
invalidate approval while retaining historical native reopen evidence. Queued
reopen requests must still match the current approval revision.

## Administrative task inspection and drain

`list-administrative-tasks` accepts `limit` and an optional `after` task key.
`get-administrative-task` accepts `device_id`, `root_guard` and `task_id`.
The list contains bounded summaries. Detail responses preserve optional native
receipts and the task's original origin. An unattributed task retains its real
native identity and stays outside public task access.

`drain-administrative-task` takes that task key, an explicit `project_alias` and
one action from `resolve`, `status`, `collect`, `fence` or `cancel`. Cancellation
also requires a stable 32-character lowercase hexadecimal `cancellation_id`.
Reuse it after a lost response. Resolve learns an unknown spec from matching
native evidence. Successful observation of existing work establishes the current
administrative route. Cancellation first resolves matching complete existing
work, fencing delayed admission only when absence or partial preparation
requires authoritative refusal. It then uses the genuine known spec for guarded
native cancellation. Its acknowledgement can leave the reservation held
until canonical closure is observed.

An observation may commit before the separate current-route binding fails.
After an administrative observation error, inspect the same task before retrying
the same action and cancellation ID. The error does not roll back recorded task
evidence or prove that a route was established.

An alternative administrative alias must have the same frozen context pin.
Binding it preserves the original public alias and owner. Saved task controls
retain root custody and frozen project identity after workspace removal.
Admission and existing-task resume require live project validation.

Root-wide recovery uses root-only namespace evidence. After restore, invoke
`refresh-project` with the same four fields as project registration to inspect a
live project and refresh its execution capability. A removed workspace remains
unready while root recovery can finish.

`list-routing-permits` exposes active metadata using a bounded device, connection
and request cursor. It helps identify retained CLI controls. Its moving page
does not establish that a missing item has closed. Page inputs require `limit`
from 1 through 100. Responses may return fewer items to fit the private response
bound. Follow the returned `next` cursor. An oversized response fails explicitly
and can be retried with a smaller limit.

### Routing CLI ownership attestation

`routing-drain-target` accepts `device_id` and returns the current recovery,
credential, connector process boot, connection generation and coverage flags.
Save this target before confirming that the prior connector instances' CLI
processes, I/O and cleanup have joined. Retain their creator-owned evidence.

`attest-routing-drained` takes `device_id`, `recovery_id`, `expected_credential`,
`expected_process_boot`, `expected_connection`, `scope` and explicit
`prior_cli_joins_confirmed` set to `true`. Copy expectations from the saved
target. `known_prior_boot` also requires `prior_boot`. An uncovered restore
device requires `all_prior_controls`, covering prior instances whose records
may be absent from the backup. Current-boot active controls remain held.

The `drained` response has `committed=true` and joins only the captured
connection. A `retired` connection status means that captured connection is
already absent. After reconnect, retry the same saved confirmation to obtain
`already_satisfied`, `committed=false` and `connection_status=unchanged` when
coverage is already established for the same credential, boot and recovery.
Changed credentials, process boot or recovery reject the saved confirmation.
The mutating path also requires the original connection. A post-commit disconnect
failure returns `disconnect_unconfirmed` with `committed=true`.

This protected operator assertion establishes prior CLI ownership joins.
Delegate's task closure and execution reservations continue to require their
existing canonical evidence. If prior joins cannot be established, routing debt
stays blocked.

## Restore safety and operational limits

Restore closes new admission and resets credentials and grants. Every prior
root's canonical inventory and the complete routing roster must be reconciled
before regular credentials or reopen approval. Missing evidence remains pending.
Inventory restart invalidates approval across the recovery; queued sends check
that their session, immutable plan, credentials, connection and approval revision
are still current.

A task keeps its original origin, request digest and spec across restore. Once
the current root is open again, explicit existing-only recovery can use that
original task binding under current dispatch rights, option ceilings and regular
credentials. New task creation still requires the current admission generation.
Ownerless evidence cannot be assigned to the next login or resumed.

An already-sent barrier from an aborted session can conflict with a later
restore. Resolve retained routing calls through a same-host census or explicit
CLI-only drain, then start a fresh explicit recovery if needed. There is no
silent rebase, replacement task submission or quota release.

**An unreachable or destroyed root can leave the entire Gateway recovery-only
indefinitely.** Retaining known reservations does not account for unknown work
admitted after the restored snapshot. Retirement or credential revocation cannot
waive inventory or free unknown execution slots. A separately authorized new
installation is a distinct accounting domain, not a quota-preserving recovery.

**One uncertain protected scan can exhaust remote cancellation/fencing capacity
across the fleet.** The fixed scan pools bound potentially running native CLI
work, including disconnected calls. Ordinary work cannot consume the protected
reserve, but that reserve can itself remain occupied. Silence, revocation or a
closed socket never proves CLI completion. Recovery requires authoritative
same-host reconciliation or drain; authorized local Delegate CLI, SSH and TUI
controls retain their independent owners. No Gateway control preempts an
accepted CLI or signals a provider directly.

The limits and release proofs are specified in [contracts](contracts.md).
