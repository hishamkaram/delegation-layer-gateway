# Product boundary

Gateway exposes authenticated HTTPS MCP and routes typed controls over outbound
connector WSS. It does not implement provider execution or a second task ledger.
Delegate alone owns admission, permanent refusal, launch, cancellation and
accepted results. Gateway operation state correlates immutable requests and
observations; possibly-sent work is resolved/fenced by its existing identity,
never retried with a fresh task ID. Connector uses public installed Delegate CLI
capabilities and fixed argv/stdin, never private task files, arbitrary remote
paths, a shell, provider APIs or Pueue.

Identity, registry, routing, contracts, transport, MCP and connector have
separate responsibilities. Root freezes shared contracts before dependent work.
The connector requires the public CLI capabilities implemented by the separate
Delegate prerequisite candidate. Validate the selected executable's capabilities
before use. Candidate tests establish compatibility for that tested build.

## Installed executables

Resolve the selected independently installed executable and run it in place.
Do not copy, stage, fingerprint or hash installed executable contents. Validate
public capabilities and required behavior; versions/paths alone are not proof.
Pinned source/archive integrity, task/result digests and diagram checksums are
separate legitimate data-integrity checks. An owned candidate build is allowed;
it does not prove compatibility of a different default installation.

## Security and evidence

External OAuth principal derives from verified issuer/subject. Gateway owns
device ownership, access scopes, legacy project grants and revocation. The
connector owns local workspace approvals and private connection credentials.
Delegate alone owns provider/model/effort support, execution permissions,
budgets, their defaults and validation. Gateway and connector forward that
intent; neither maintains a second execution ceiling. Discovery is dated
advice, never an execution allowlist. Revocation is checked before
sends/responses. Recovery never restores lost authority by
assumption. Request/reply success, online transport and cancellation acceptance
are not execution success, readiness or confirmed closure. No prompts, requested
file/result content, tokens, keys, raw native errors or user paths in diagnostics
or metrics. Requested file names and bytes are authorized response data, not
diagnostic output. Do not scan, classify, filter or redact requested content.
Approved workspaces and automatic OS temp scopes are routing boundaries, never
an OS sandbox for provider execution.

No provider adapters, private supervisor control, distribution machinery or
external service provisioning belong in this repository. See [architecture](../../docs/architecture.md)
for current milestone contracts and implementation limits.
