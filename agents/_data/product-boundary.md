# Product boundary

Gateway exposes authenticated HTTPS MCP and routes typed controls over outbound
connector WSS. It does not implement provider execution or a second task ledger.
Delegate alone owns admission, permanent refusal, launch, cancellation and
accepted results. Gateway operation state correlates immutable requests and
observations; possibly-sent work is resolved/fenced by its existing identity,
never retried with a fresh task ID. Connector uses public installed Delegate CLI
capabilities and fixed argv/stdin, never private task files, arbitrary remote
paths, a shell, provider APIs or Pueue.

Identity, registry, routing, contracts/policy, transport, MCP and connector have
separate responsibilities. Root freezes shared contracts before dependent work.
Public future connector commands remain planned until compatible installed
Delegate capability tests prove them. M0 scaffolding does not implement them.

## Installed executables

Resolve the selected independently installed executable and run it in place.
Do not copy, stage, fingerprint or hash installed executable contents. Validate
public capabilities and required behavior; versions/paths alone are not proof.
Pinned source/archive integrity, task/result digests and diagram checksums are
separate legitimate data-integrity checks. An owned candidate build is allowed;
it does not prove compatibility of a different default installation.

## Security and evidence

External OAuth principal derives from verified issuer/subject. Gateway owns
per-device/project grants; connector owns a stricter local ceiling. Revocation
is checked before sends/responses. Recovery never restores lost authority by
assumption. Request/reply success, online transport and cancellation acceptance
are not execution success, readiness or confirmed closure. No prompts, result
content, tokens, keys, raw native errors or user paths in public diagnostics.

No provider adapters, private supervisor control, distribution machinery or
external service provisioning belong in this repository. See [architecture](../../docs/architecture.md)
for current milestone contracts and implementation limits.
