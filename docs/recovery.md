# Root initialization and recovery

The candidate implements root initialization, fleet restore orchestration and
private administrative task controls. Integrated verification remains in progress.
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
explicitly inspects Delegate again so the connector can publish refreshed
capabilities. Registry readiness, dated connector capabilities and provider
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

Migration upgrades schema 6 to 7 atomically and preserves the existing identity,
grants, task correlations, observations and routing evidence. Running it against
a valid schema-7 database succeeds without replacing that authority. The offline
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
