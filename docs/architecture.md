# Architecture

Status: approved target design; implementation and live acceptance remain pending.

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

Device IDs are stable opaque identities; names may collide. Online presence does
not establish Delegate compatibility or provider authentication. Every operation
requires current grants and the connector's local ceiling. Explicit device and
project selection never silently falls back.

## Admission and recovery

Preparation freezes the brief, selected provider/model/effort/permissions/budget,
context guards and random operation/task identities. It launches nothing.
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

This is a single-instance MVP with SQLite, no broker, no offline paid-work queue,
no arbitrary remote shell/filesystem tools and no duplicate execution engine.
Existing local, SSH and TUI workflows continue through Delegate's own owners.
