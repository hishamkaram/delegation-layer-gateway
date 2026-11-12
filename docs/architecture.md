# Architecture

Status: implementation in progress; integrated and live acceptance remain open.

See the maintained [component and operation-safety diagrams](../diagrams/README.md).

## Owners and invariant

| Owner | Writes | Readers | Invariant |
| --- | --- | --- | --- |
| Gateway registry | Enrollment, credentials, grants, routing correlations and reservations | MCP handlers, device transport, local admin | One durable request identity; no blind replay or authority inferred from a timeout |
| Connector configuration | Operator-bound project aliases and local ceilings | Connector policy and public CLI adapter | Remote requests cannot select arbitrary paths, commands or wider permissions |
| Delegate | Admission/refusal, tasks, supervision, cancellation and accepted results | Connector through versioned public interfaces | Exactly one execution authority; accepted outcome and canonical closure are distinct from transport success |
| Identity provider | User authentication and access tokens | Gateway verifier | Principal comes from validated issuer/subject, never tool arguments or OAuth client ID |

The dependency direction is transport/UI -> orchestration -> pure policy/data.
SQLite and network/clock/process access stay behind their owners. Cached task
observations carry freshness and never replace Delegate authority.

Accepted results and execution closure are separate facts. Delegate can publish
an outcome before its worker's native Wait. Gateway may return verified accepted
bytes while retaining the operation reservation. Only canonical execution-closure
proof, a fresh matching owner-confirmed termination, durable permanent refusal,
or definitely-unsent expiry releases capacity. Publication and generic
`liveness=ended` never substitute for that proof. This follows Delegate's existing
[publication-before-Wait regression](https://github.com/hishamkaram/delegation-layer/blob/0eed5e28288628490c6fb0297616f4d64d4584c9/internal/taskdir/readonly_completion_race_test.go#L38).

CLI project tokens contain encoded local directory identity. They stay inside
the connector. Wire and registry context guards use `ctx1_` plus SHA-256 of the
locally pinned CLI token; the adapter verifies and normalizes public receipts.
MCP output contains project aliases, not CLI tokens or local paths.

## Connectivity and identity

One Gateway process serves HTTPS MCP/enrollment and a separate device-certificate
WSS listener. Devices need outbound connectivity only. User OAuth and device
certificates have independent trust and revocation paths. Auth0 is the first
documented reference issuer; live interoperability must be demonstrated.

The server composition owns TLS and exact public Host/Origin validation before
authentication. The MCP SDK's additional loopback-host heuristic is disabled:
the supported reverse proxy connects over loopback while preserving that public
Host. The existing composition guard remains mandatory for the MCP adapter.
The transport supports protocol versions `2026-07-28`, `2025-11-25` and
`2025-06-18`. It admits one JSON-RPC message per authenticated HTTP request.
Arrays sent as `application/json` receive HTTP 400 before SDK dispatch. Older batch-requiring versions
are excluded. JSON request bodies are bounded to 1 MiB, including whitespace.
This keeps one HTTP rate/concurrency admission from fanning out into a batch of
tool executions. The SDK still owns message parsing and version negotiation.
Gateway and SDK each buffer the bounded body. Operators should allow roughly
256 MiB plus allocation overhead for both copies at the maximum 128 concurrent
requests; normal request bodies consume less.

Connector configuration pins the HTTPS/WSS server authority in `trust_ca_file`
and the issued device-certificate authority in `device_ca_file`. Both files are
operator-owned CA bundles. Device credential validation never expands server
trust. Omitting `device_ca_file` preserves existing configurations that use the
same authority for both roles. Enrollment, stored credentials, renewal and
reconnect use the device authority for client-certificate validation.

Device IDs are stable opaque identities; names may collide. Online presence
requires the completed authenticated wire handshake, including routing and
capability exchange, and a session that is not closing. Transport's existing
handshake-completion signal is authoritative; registering a candidate session
alone does not make it online. Online still does not establish Delegate
compatibility or provider authentication. Every operation requires current grants
and the connector's local ceiling. Explicit device and project selection never
silently falls back.

Transport owns each outbound write and its completion signal. A completed
reservation response waits for both the peer reply and the originating writer
to finish, including its cancellation cleanup. Otherwise a caller cancelling
its completed request could close a WebSocket still finishing that write.
Observer cancellation remains bounded and does not assume the writer stopped.
Session teardown retains its existing precedence: it can discard an unconsumed
reply and return an offline error. These are connection-lifetime rules, not task
outcome or execution-closure evidence.

## Admission and recovery

Registry creation is explicit: `gateway init --database ABS` creates a new private
database and generates its Gateway identity and credential epoch. Serving opens
an existing database and requires its expected Gateway identity; missing or
incomplete storage never silently becomes a fresh instance. `gateway identity
--database ABS` reads only the persisted identity while the instance is stopped.

Registering a project binds its alias and exact context guards. It cannot choose
an admission generation or make a root execution-ready. Registry owns eligibility
once per device/root, shared by its aliases. New-root initialization records a
durable session and generation before sending an expected-absent Delegate
barrier. Complete canonical inventory, approval and guarded reopen must finish
before admission opens. Adding a root does not reset fleet credentials or grants.

An interrupted initialization resumes its recorded phase and identity. An
unexpected existing namespace requires explicit recovery; it is never adopted.
Administrative abandonment retains evidence and reservations and requires an
explicit fleet restore. Queued barrier and reopen sends revalidate the active
session and exact durable plan before writing. An already-sent conflicting
barrier can require a fresh explicit restore after a routing census or drain;
there is no automatic rebase or replacement task submission.
See [operator recovery and its availability limits](recovery.md).

Preparation freezes the brief, selected provider/model/effort/permissions/budget,
context guards and random operation/task identities. It launches nothing.
The versioned request digest binds these immutable fields and the brief's SHA-256;
restored attribution can verify the digest without recovering brief plaintext.
Confirmation checks the encoded frame before persisting possible-send, then
sends to the selected connected device. An uncertain response never permits a
replacement identity or blind redispatch.

Delegate's public boundary provides passive resolution, explicitly authorized
existing-only recovery and durable refusal serialized against creation. Partial
creation needs canonical no-launch proof; unattributed recovery is operator-only.
No refusal is a claim of zero helper cost or completed cleanup.

Gateway restart resolves correlations without launching them again. Snapshot
restore resets credentials/grants and reserves all capacity until each prior
destination applies a new Delegate admission-generation barrier and returns a
complete canonical inventory. Stale preparation loses before writing fragments.
Reopening revalidates inventory under exclusive maintenance ownership. Missing
rosters, evidence or devices keep restore blocked; revocation never frees unknown
execution capacity.

## Privacy and deployment

Gateway processes plaintext in memory. Draft storage is sensitive and bounded;
results are not persisted by Gateway. Operators must protect storage/backups.
Audit uses an explicit metadata allowlist, not redaction of arbitrary native
output. No external telemetry is required. The local admin socket is not a
public administration API.

The `device_credential_denied` audit event records a fresh registration whose
verified client-certificate identity Registry rejected with a sole policy
denial. Its `credential` object contains only `device_id`, `epoch` and
`generation`, copied from public certificate identity metadata. It includes no
certificate bytes, keys, tokens or native error. Existing-session checks,
duplicate connections and wrapped storage failures do not produce this event.
Metrics count the fixed event code without identity labels. Recorder failures
remain sticky on protected admin health and do not change authentication.
This event establishes Registry rejection of that identity, not a unique
certificate fingerprint or an exclusive reason for rejection.

This is a single-instance MVP with SQLite, no broker, no offline paid-work queue,
no arbitrary remote shell/filesystem tools and no duplicate execution engine.
Existing local, SSH and TUI workflows continue through Delegate's own owners.
