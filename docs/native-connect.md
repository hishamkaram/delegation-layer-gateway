# Deploy Gateway and connect Delegate

This branch implements the remote Delegate experience for the next Gateway and
Delegate releases. Engineering gates, independent integrated review and the new
live acceptance remain incomplete. The [dated earlier evidence](verification.md)
belongs to its recorded revisions and does not prove this candidate.

The normal device experience is `delegate gateway connect HTTPS_URL`. Native
owns its user service and embeds the Gateway client; a separate connector
installation or tmux session is not required. Gateway continues to own routing
and access. Delegate continues to own tasks, supervision and accepted results.

## Configure the hosted Gateway

Use [deployment](deployment.md) for the private database, device CA, HTTPS
certificate, private configuration, issuer and listeners. A new database uses
schema 10. For an older supported database, stop Gateway and its other
writers, keep a protected backup, then explicitly migrate it:

```sh
gateway migrate --database /absolute/private/state/gateway.sqlite --preview
gateway migrate --database /absolute/private/state/gateway.sqlite --accept-execution-policy-removal
```

No startup path silently upgrades storage. Migration keeps the Gateway identity
and existing ownership, scopes, grants and history. The explicit acceptance removes
saved execution ceilings. It does not adopt legacy devices or dispatch work.

Add this optional object to the existing Gateway JSON configuration:

```json
{
  "device_login": {
    "native_client_id": "PUBLIC_NATIVE_CLIENT_ID",
    "device_wss_url": "wss://gateway.example.com:8443/device"
  }
}
```

Keep the existing MCP OAuth application unchanged. In Auth0, create a separate
**Native** application for device login. Use token endpoint authentication
**None**, OIDC Conformant, and the **Device Code** grant. This implementation
does not request refresh tokens or use Implicit, Password or Client Credentials
grants. Enable a login connection for this application.
See [Auth0's Device Authorization prerequisites](https://auth0.com/docs/quickstart/native/device/interactive).

On the existing custom API, add these two permissions:

| Permission | Description |
| --- | --- |
| `device:enroll` | Register your own Gateway devices |
| `device:manage` | Revoke or replace your own device credentials |

In the API's application access settings, edit the Native application's
**User-delegated Access** and allow those permissions. Leave its Client Access
and Anonymous Access unauthorized. The Native client ID is public configuration;
there is no Native client secret to distribute. Issued scopes alone do not
create Gateway eligibility.

Run the parameterized [Nginx helper](nginx-setup.md) for your hostname. Its HTTPS
allowlist includes the descriptor, OAuth metadata, enrollment and owner
revocation routes. It does not proxy the private admin socket or metrics.
Keep the direct device mTLS listener reachable on the configured port.

When using that loopback Nginx proxy, set
`"trust_loopback_proxy_client_ip": true` at the top level of Gateway's private
configuration. Nginx overwrites `X-Real-IP` with its actual client address.
Gateway accepts this rate-limit key only from a loopback socket when explicitly
enabled. It never uses that header for identity or authorization. The default
is false for a directly exposed Gateway. Descriptor traffic has a separate
bucket from enrollment and revocation.
Any local process can choose a rate-limit key when loopback trust is enabled;
local accounts and the reverse proxy belong to this trusted host boundary.

Start Gateway with its private configuration:

```sh
gateway serve --config /absolute/private/gateway.json
```

From the Gateway host, allow the exact issuer subject that will log in. Read it
from the identity provider's user record; an email address or display name is
not a substitute for its exact subject. `--config` supplies the configured issuer
and private admin socket:

```sh
gateway users allow --config /absolute/private/gateway.json \
  --subject 'EXACT_IDENTITY_PROVIDER_SUBJECT' --max-devices 2
gateway users show --config /absolute/private/gateway.json \
  --subject 'EXACT_IDENTITY_PROVIDER_SUBJECT'
```

The default owner access scopes cover inventory, dispatch, task read and task
cancellation. Use repeated `--scope` flags to deliberately choose access scopes.
These govern access to the device; they do not choose providers, execution
permissions or budgets. Delegate validates those options for each task using
its own supported defaults. Owner access changes apply live to all owned devices.

## Connect a device

Use the compatible Native candidate containing `delegate gateway` and its
workspace-constrained root contract. Native's own installation and engineering
instructions remain authoritative. The normal root resolver chooses the state;
an existing legacy root needs Native's explicit offline cutover first. Connect
never upgrades a busy root or restarts its shared supervisor automatically.
Follow [Native's root cutover procedure](https://github.com/hishamkaram/delegation-layer/blob/0a17c93cda0717bdd8cf28d24142e3c35d66d38d/docs/gateway-connect.md#native-root-and-profile)
before retrying a connection that reports `root_cutover_required`.

For a new custom Native state root, check its canonical UTF-8 path length before
enrollment: at most 89 bytes on macOS or 93 on Linux. Native's owner socket adds
14 bytes to that path. Keep builds, evidence and approved workspaces separate
from the short state root; project paths do not share this socket-path limit.
Do not move existing task state to shorten it. See
[Native's socket-path guidance](https://github.com/hishamkaram/delegation-layer/blob/c74d79cd4853cea0afdc03f9f4a83261cc91729e/docs/troubleshooting.md#supervisor-configuration-fails).

```sh
delegate gateway connect https://gateway.example.com
```

The command performs one Device Authorization Flow, enrolls the device and
installs/starts its user service. `--headless` prints that same challenge instead
of opening a local browser; approve it on another device:

```sh
delegate gateway connect https://gateway.example.com --headless
```

Use `--name mac-home` to choose a display name; omission uses the local hostname.
In a cloud prompt, a user can refer to that name. The MCP client must first call
`list_devices`, match one authorized device and retain its `device_id` for the
operation. Tool calls require the ID; names are not unique identifiers. An
ambiguous name or unavailable selected device requires clarification, never a
silent switch to another device.

For a foreground process instead of service installation:

```sh
delegate gateway connect https://gateway.example.com --foreground
```

The default profile is under the selected Native state root. Use `--profile`
only to deliberately select another absolute private profile directory. Source,
Gateway identity, issuer/resource and trust pins cannot silently change.
Local `status` and `doctor` are observations of local configuration, not proof
of online connectivity, provider login or execution readiness.

## Connect without any browser

On Gateway, mint a one-device token for an already eligible subject. The output
parent directory must be owned and private; the output filename must not exist:

```sh
gateway devices enrollment-token --config /absolute/private/gateway.json \
  --subject 'EXACT_IDENTITY_PROVIDER_SUBJECT' --name build-device \
  --output-file /absolute/private/new-device-token.json
```

Transfer that private file through an authorized secure channel, then run on
the selected device:

```sh
delegate gateway connect https://gateway.example.com \
  --token-file /absolute/private/new-device-token.json
```

`--token-file -` reads the same JSON from stdin. Tokens are never command-line
values. The one-device grant lasts ten minutes, reserves device capacity and
cannot adopt a legacy device. The client persists its CSR before redemption;
retrying redemption preserves that identity. A valid token or enrolled
certificate does not require contacting the OAuth issuer.

The admin mint returns the raw secret once. On uncertain delivery, retain its
exclusive output file, even if empty, and inspect the owner's inventory or wait
for expiry. Repeating the exact CLI command cannot mint again because that file
already exists. Choosing another output file is an explicit new mint, not a
recovery of the lost token. There is no automatic remint or secret recovery.

## Approve a workspace once

New profiles expose no workspace. On the device, approve an existing ancestor
directory:

```sh
delegate gateway workspace allow /absolute/work --alias work
delegate gateway workspace list
```

The approval saves this directory as a routing boundary. It needs no provider,
model, read/write mode or budget flags. Providers and their options come from
Delegate; choose them per task. New profiles do not copy execution policies
into workspace approvals. Existing policy-bearing profiles require the explicit
upgrade below before the new connector runs.

The cloud client uses the device's returned scope ID and relative paths:

1. `list_devices`: find the requested name, retain its exact device ID, and stop
   if the name is ambiguous or that device is offline.
2. `list_workspaces`: obtain approved workspace and automatic temporary scope IDs.
3. `list_directory`: browse the selected scope, starting at `.`; follow page
   cursors. Hidden files and directories are included. `inspect_git` returns
   structural Git candidates without executing Git or requiring a repository.
4. `read_file`: request the files/ranges needed to identify the project. Bytes
   are returned as base64, with text where valid UTF-8. There is no content scan,
   extension allowlist or content redaction. A file version is an optimistic
   change check, not an atomic snapshot.
5. `get_capabilities` with `selection`: inspect dated Native provider support.
   Use `list_models` explicitly when model discovery is needed. Discovery may
   launch Native's bounded inspection process; it is not a task or an allowlist.
6. `prepare_dispatch`: save a random 32-character lowercase hexadecimal
   `request_id` before calling. Supply the exact device, `selection` (scope ID
   and relative project path), brief and `native_options`. Select a provider;
   omit optional fields to use Native defaults, and include required provider
   options when advertised.
7. `dispatch_task`: confirm the returned operation exactly once. On uncertainty,
   resolve that same operation. Never replace it or switch device automatically.

No `resolve_project` or manual project alias is needed for this flow. The legacy
alias tools remain for old project registrations and saved task handles. New
preparation does not allocate a permanent project pin or consume a legacy
1,024-pin lifetime budget. Reusing the same preparation ID and same input returns
the original operation even after a response is lost, the device goes offline,
or its request body expires. Changing input under that ID conflicts.

Filesystem access requires both `task:dispatch` and `task:read` in the verified
client token and current owner access policy. Inventory alone does not expose
files. Revocation is rechecked before sending and returning data. OS permissions
still apply. Workspace approval is routing authority, not an OS sandbox for a
provider process.

Linux exposes the whole `/tmp` automatically. macOS exposes both the current
user's OS temporary directory and shared `/tmp` (canonical `/private/tmp`),
deduplicating the same canonical directory. This does not expose all of
`/var/folders` or `/var/tmp`. No manual temporary-workspace registration is needed.

If live temporary-scope discovery fails, `list_workspaces` can still return dated
approved workspaces with `scope_discovery_error`. Do not treat that partial
inventory as an empty temporary directory or proof of execution readiness.
Directory and file requests still require current access and a live device.

Approvals use canonical path semantics: replacing or recloning the ancestor or
project at the same path is allowed. A new command selects the current directory;
a running command retains its working directory. Missing directories or symlinks
escaping the selected scope refuse a new launch. Removing an approval prevents
new work but preserves authorized historical status, cancellation and results.
Device or principal revocation still denies those controls.

### Upgrade an existing connection

Keep the original Native root and profile; do not re-register, copy task state or
edit private profile JSON. Run the new installed Delegate binary:

```sh
delegate gateway upgrade --preview --json
delegate gateway upgrade --accept-execution-policy-removal --json
```

The preview is read-only. The apply command coordinates the existing service and
Native installation owners, removes saved duplicate execution policy, and changes
only the selected executable under the same-source compare-and-swap guard. Device
identity, credential, Native root, disabled workspace revisions, old pins and task
history remain. An interrupted handoff resumes through those same owners; it does
not mint another registration. A pending Native upgrade is resumed by its exact
operation identity. Failed prerequisites are reported; do not delete state to make
the command pass.

For a standalone legacy connector configuration, stop that connector first:

```sh
gateway connector migrate --config /absolute/private/connector.json --preview
gateway connector migrate --config /absolute/private/connector.json --accept-execution-policy-removal
```

The static migration preserves its credential directory and project guard bytes.
It does not start the connector. Old configurations are refused until migrated.

### Refresh ChatGPT actions after an upgrade

An existing ChatGPT connection can still expose its earlier action set after
Gateway adds tools. Refresh requires a valid connection and permission to manage
it. For a directly connected custom MCP server, open its connection in
**ChatGPT Plugins → Refresh**, then confirm that `list_workspaces`, `list_directory`, `read_file`, `inspect_git` and
`list_models` appear. See [OpenAI's direct-connection refresh procedure](https://developers.openai.com/plugins/deploy/connect-chatgpt#refresh-metadata).

For a workspace-published app, an admin/owner must review and publish the update.
Use **Workspace settings → Apps → ⋯ → Action control → Refresh**, or the
publish-time **Configure Actions** control where available. New actions can be
disabled by default; enable the required actions before publishing. The retained
app settings are also reachable from **Admin Console → Plugins → Manage Legacy
Apps**. Ordinary members must ask their app manager. See [OpenAI's workspace
action-control guidance](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt).
Start a new chat and select the updated connection before testing again.

If inventory works but the required browsing tools are absent, stop before preparing a
task. Compare the authenticated server `tools/list` response with ChatGPT's
enabled actions. Refreshing action metadata does not enroll a device, alter
workspace approvals or dispatch a task.

For cloud login and refresh configuration, use the [week-long connection guide](cloud-login.md).

## Operate and recover

On `collect_result`, nonretryable `result_unavailable` means Native has rejected
publication for that task. There are no accepted result bytes to read. Preserve
the operation and task IDs; inspect Native's public status/collection guidance
for the cause. Gateway does not expose raw provider diagnostics or run provider
login, retry or replacement work. Execution closure is independent: a rejected
outcome can still have an open execution reservation, and a closed execution can
still be waiting for publication. Both Gateway and the Native connector SDK
must include the rejection-projection correction; older adapters can still
report pending for rejected output. A corrected Native connector with an older
Gateway can report terminal execution without a descriptor or final collection
error; upgrade both sides before verifying the corrected behavior.

Native exposes explicit `gateway service install|start|stop|status|uninstall`
commands and `gateway serve`. Linux requires the intended user's systemd
manager; macOS requires its GUI LaunchAgent context. Missing manager/session
prerequisites are explicit errors. No SSH background-context fallback or hidden
sudo configuration is performed.

```sh
delegate gateway status
delegate gateway doctor
delegate gateway disconnect
```

Disconnect stops/uninstalls this profile's connector after joined local runtime
ownership. It preserves task history, pins and credentials. It does not cancel
provider tasks. `disconnect --revoke` additionally requests fresh owner-management
login before revoking that device; `--headless` can present that login elsewhere.
Revocation never proves task termination.

The local Gateway operator can revoke an exact device without an interactive
login, or disable an owner's eligibility for all its devices:

```sh
gateway devices revoke --config /absolute/private/gateway.json --device EXACT_DEVICE_ID
gateway users disable --config /absolute/private/gateway.json \
  --subject 'EXACT_IDENTITY_PROVIDER_SUBJECT'
```

Only network reconnection is automatic. Process autorestart is disabled. After
a crash, preserve the profile and uncertain routing permits. Restarting may
connect in an admission-blocked state; use the existing protected
[routing recovery procedure](recovery.md) when prior CLI ownership cannot be
proved joined. Timeouts, socket loss, lock availability and accepted results
are not substitutes for that proof. Do not delete state to clear uncertainty.

## Verify a candidate locally

Use the repository-pinned Go compiler with `GOTOOLCHAIN=local`. Build Gateway
and the acceptance helper from the Gateway checkout with `GOWORK=off`:

```sh
GOWORK=off go build -o /absolute/private/bin/gateway ./cmd/gateway
GOWORK=off go build -tags=e2e -o /absolute/private/bin/gateway-e2e-fixture ./internal/e2e
```

An unpublished Native candidate may still pin the previous released SDK. Test
that candidate against the actual Gateway checkout using a new workspace file
outside both repositories; its private parent directory must already exist:

```sh
GOWORK=/absolute/private/candidate.work go work init /absolute/gateway-checkout /absolute/native-candidate-checkout
```

In the matching Native candidate checkout, build the Native pair together:

```sh
GOWORK=/absolute/private/candidate.work go build -o /absolute/private/native/bin/delegate ./cmd/delegate
GOWORK=/absolute/private/candidate.work go build -o /absolute/private/native/bin/delegate-run ./cmd/delegate-run
```

Never commit that workspace file or a local module replacement. Once Native pins
the reviewed published SDK revision, normal builds use `GOWORK=off` again.

From the Gateway checkout, select those candidates, the installed Pueue pair
and an existing private work parent explicitly:

```sh
python3 scripts/e2e_native_connect.py \
  --gateway /absolute/private/bin/gateway \
  --fixture-tool /absolute/private/bin/gateway-e2e-fixture \
  --delegate /absolute/private/native/bin/delegate \
  --delegate-run /absolute/private/native/bin/delegate-run \
  --pueue /absolute/installed/pueue \
  --pueued /absolute/installed/pueued \
  --delegate-repository /absolute/native-candidate-checkout \
  --work-parent /absolute/private/acceptance --run-native --compact-routes
```

This scenario first browses descendants created after approval, paginates hidden
and non-UTF-8 names, reads exact byte ranges, inspects structural Git markers,
rejects scope escapes and, on Linux, reads an owned child of the automatic whole
`/tmp` scope. Fresh public Native profile previews and canonical observations
check that browsing created no project pins, operations or tasks. Requested-byte
sentinels, including their range and base64 forms, must stay out of product
diagnostics, audit and metrics; authorized response captures remain separate.

`--compact-routes` exercises scope-relative selection and compact request bindings
without project pins. Omitting it retains the legacy project-alias scenario.

It then runs two local embedded connectors and three literal fixture tasks,
with a four-attempt safety cap and one active task at a time. It uses no paid
provider. A passing result reports `native_connect_passed` and
`cleanup_confirmed: true`; evidence stays in the reported private directory.
Linux temporary-fixture removal additionally reports
`filesystem_temp_cleanup_confirmed: true` after the process joins.
Unknown original process ownership blocks descendant cleanup and retains
resources. This does not verify browser login, desktop services, installed
providers, physical networks or Cloud clients; those need separate live checks.
The literal provider fixture does not save a usable session checkpoint, so this
scenario does not prove successful continuation. Test `prepare_continuation`
separately against an installed provider's accepted predecessor and checkpoint.
