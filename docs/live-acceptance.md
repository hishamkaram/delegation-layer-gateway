# Opt-in live acceptance

These developer tools use the existing tagged Go MCP SDK client and Delegate's
maintained process owners. They do not install a provider, enroll devices,
provision Auth0, create a public deployment or launch ChatGPT. Gateway and
Delegate retain their production responsibilities.

Keep configuration, tokens, receipts and captures outside the public checkout.
Configuration and token files must be owned regular 0600 files. The selected
Native source checkout must contain its maintained acceptance harness. Select
installed executables by absolute path and run them in place.

All local paths must be canonical absolute paths, including the configuration,
receipt parent, token file, helper and Native checkout. Use physical paths rather
than symlink aliases. On macOS, `/var/...` may resolve to `/private/var/...`;
provide the physical form. Invalid aliases are rejected before network work.

## One installed-provider task

An operator must first authorize the environment and a finite monetary budget.
The tool enforces one task and a finite task duration; those limits do not
establish a monetary cap. Use a project and provider that permit read-only work.
Online presence and advertised providers do not establish account authentication.

Example private configuration:

```json
{
  "endpoint": "https://gateway.example.com/mcp",
  "helper": "/absolute/gateway/bin/gateway-e2e-fixture",
  "token_file": "/absolute/private/access-token.json",
  "native_repository": "/absolute/delegation-layer",
  "device_id": "selected-device",
  "project_alias": "selected-project",
  "provider": "codex:exec",
  "permission": "read-only",
  "budget_seconds": 60,
  "max_tasks": 1
}
```

Optional `model` and `effort` select advertised values explicitly. Omitting them
uses the provider's native defaults. The token file contains only
`{"token":"ACCESS_TOKEN"}`. Supply an access token authorized for the Gateway,
with the required inventory, dispatch, read and cancel scopes and target grants.
Never substitute an OAuth client secret for an access token.

```sh
make e2e-provider E2E_ARGS='--run-real-provider --config /absolute/private/provider.json --receipt-directory /absolute/private/provider-run-new'
```

The receipt directory must not exist for a new run. Current capabilities must
allow task reads and cancellation as well as the exact requested dispatch.
Every operation still rechecks authorization; later expiry or revocation can
prevent observation and cleanup.

The driver preserves its intent before preparing, and the original operation,
task and cancellation identities before dispatching. It never prepares a
replacement after an ambiguous response. Success requires an accepted result,
verified chunk offsets/length/SHA-256 and the canary, plus canonical execution
closure. Results and prompts stay in private evidence; they are not printed.
Helper-process joins and provider-task closure are separate evidence.

## Observe or cancel the original operation

Resume uses the original locked receipt and cannot override the destination,
request or identity. Each attempt retains its own private helper captures.
Resume never prepares or dispatches another task.

```sh
python3 scripts/e2e_live.py resume --receipt-directory /absolute/private/provider-run-new --observe
python3 scripts/e2e_live.py resume --receipt-directory /absolute/private/provider-run-new --cancel
```

A successful cancellation recovery proves the reported cleanup disposition; it
is not installed-provider acceptance. Uncertain preparation without a returned
operation identity remains an orphan intent: retain it for investigation rather
than creating replacement work. A timeout, cancellation acknowledgement or
saved receipt phase never proves execution closure. Keep unresolved receipts.

Observation mode never sends task mutations, including during error or interrupt
cleanup. It joins only its own helpers and reports unverified task closure when
observation cannot finish. The original provider run and explicit cancellation
mode retain cancellation cleanup using the original identity.

Each attempt writes its final summary after releasing the receipt lease. A
concurrent resume in that short gap can see the prior attempt as unverified and
must report that uncertainty. It cannot convert missing closure proof into a
pass; retain the receipts for investigation.

Each summary scopes helper joins to its current controller. Resume also checks
private resource-closure proof from every prior attempt. Missing, crashed,
legacy or unjoined prior-controller proof blocks overall/provider acceptance,
even if a new observation confirms the original task closed. Same-identity
observation/cancellation remains available, and its task closure is reported
separately. Time passing does not clear this resource uncertainty. The tool does
not search for or adopt an earlier process.

## System-trusted HTTPS and SDK preflight

The preflight launches no provider tasks. Its private configuration uses the
same four common fields, plus the exact issuer and two distinct device targets:

```json
{
  "endpoint": "https://gateway.example.com/mcp",
  "helper": "/absolute/gateway/bin/gateway-e2e-fixture",
  "token_file": "/absolute/private/access-token.json",
  "native_repository": "/absolute/delegation-layer",
  "expected_issuer": "https://tenant.example.auth0.com/",
  "targets": [
    {"device_id":"device-a","project_alias":"project-a"},
    {"device_id":"device-b","project_alias":"project-b"}
  ]
}
```

```sh
make e2e-external E2E_ARGS='--run-external-preflight --config /absolute/private/preflight.json --receipt-directory /absolute/private/preflight-run-new'
```

The tokenless metadata request checks the configured resource and issuer. SDK
calls independently check access-token acceptance and the explicit targets.
Metadata does not advertise an OAuth audience field. Neither request follows
advertised issuer URLs or redirects. Bearer delivery is pinned to the configured
MCP URL; system TLS roots and hostname verification remain enabled.

This establishes system-trusted HTTPS/SDK behavior from the test host. It does
not establish Internet reachability from ChatGPT, different device WANs,
installed-provider execution or actual ChatGPT Cloud compatibility. Record those
acceptance categories separately in [verification](verification.md).

## Resource and trust limits

The helper's default fixture mode remains IP/CA constrained. Live tools select
system mode explicitly and cannot supply fixture CA/IP overrides. Each HTTP
response is bounded to 1 MiB; helper stdout is bounded to 2 MiB including its
newline. Persistent streaming is not an acceptance requirement: the Gateway
uses stateless JSON-response MCP.

The main helper operation has a 40-second context and finite HTTP deadlines.
SDK session cleanup can take a separate bounded interval for a stateful server;
a helper wait timeout is not closure proof. The owner retains captures and
unresolved process/task evidence on failure or interruption.

The configured engineering gate includes the tagged helper's vet, lint and race
checks. Unit tests and local fixture execution do not prove the live categories.
