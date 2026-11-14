# Deploy Gateway and connect Delegate

This extension is an implementation candidate. Its browser, unattended,
dynamic-project and service flows need their own live acceptance. Earlier MVP
acceptance does not establish that these additions work on a deployed host.
See [verification](verification.md) for the recorded checks and open gates.

The normal device experience is `delegate gateway connect HTTPS_URL`. Native
owns its user service and embeds the Gateway client; a separate connector
installation or tmux session is not required. Gateway continues to own routing
and access. Delegate continues to own tasks, supervision and accepted results.

## Configure the hosted Gateway

Use [deployment](deployment.md) for the private database, device CA, HTTPS
certificate, private configuration, issuer and listeners. A new database uses
schema 9. For an existing schema 6, 7 or 8 database, stop Gateway and its other
writers, keep a protected backup, then explicitly migrate it:

```sh
gateway migrate --database /absolute/private/state/gateway.sqlite
```

No startup path silently upgrades storage. Migration keeps the Gateway identity
and existing grants/history; it does not adopt existing devices as owned devices.

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
  --subject 'EXACT_IDENTITY_PROVIDER_SUBJECT' --provider claude:print \
  --max-budget-seconds 60 --max-devices 2
gateway users show --config /absolute/private/gateway.json \
  --subject 'EXACT_IDENTITY_PROVIDER_SUBJECT'
```

Repeat `--provider` for additional explicitly approved providers. The default
permission is read-only. Owner policies apply live to every owned device and
resolved project; Gateway does not generate duplicate per-project grants.

## Connect a device

Use the compatible Native candidate containing `delegate gateway` and its
workspace-constrained root contract. Native's own installation and engineering
instructions remain authoritative. The normal root resolver chooses the state;
an existing legacy root needs Native's explicit offline cutover first. Connect
never upgrades a busy root or restarts its shared supervisor automatically.
Follow [Native's root cutover procedure](https://github.com/hishamkaram/delegation-layer/blob/0a17c93cda0717bdd8cf28d24142e3c35d66d38d/docs/gateway-connect.md#native-root-and-profile)
before retrying a connection that reports `root_cutover_required`.

```sh
delegate gateway connect https://gateway.example.com
```

The command performs one Device Authorization Flow, enrolls the device and
installs/starts its user service. `--headless` prints that same challenge instead
of opening a local browser; approve it on another device:

```sh
delegate gateway connect https://gateway.example.com --headless
```

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
directory and its local provider ceiling:

```sh
delegate gateway workspace allow /absolute/work --alias work --provider claude:print
delegate gateway workspace list
```

The MCP client then selects the explicit device and workspace using
`list_devices` and `list_workspaces`. It calls `resolve_project` with a saved
random 32-character lowercase hexadecimal `request_id`, that workspace ID and
an existing relative directory such as `team/services/api` or `.`. Gateway does
not scan, clone, create directories or switch devices. Save the returned project
handle and reuse it for tasks; do not resolve a new handle for every dispatch.

The same request ID returns its original binding after retries or directory
replacement. An approval binds the canonical path: replacing or recloning the
ancestor or project at that same path is allowed. Each new command selects the
current directory; an already running command keeps its original working
directory. Replacement or removal alone does not invalidate its accepted result.
Missing directories, traversal and symlinks escaping the approved ancestor
refuse a new launch. Project handles never select another device or path.

Changing a request's selector conflicts. There are at most 1,024 retained
pins, including tombstones, with a separate four-MiB encoded pin budget; either
limit can stop new resolutions. Existing identities are not evicted.

Gateway separately retains at most 1,024 resolution request IDs per device,
including attempts that failed or remain unfinished. Retry the original ID;
changing to a new ID uses another slot. The advertised `project_budget` describes
Native's committed local pins, not Gateway's retained request count. There is no
automatic reset or compaction command. Reaching this limit blocks new
resolutions while preserving existing task controls and evidence.

`prepare_dispatch` and `dispatch_task` use the resolved handle and stable
operation identity. Fresh targeted capabilities are checked before preparation
and sending; the connector checks the current local ceiling through CLI Start.
Policy edits do not rewrite frozen task identity. Removing a workspace blocks
new resolution, admission and resume while preserving authorized saved task
status, cancellation and result retrieval. Device/principal revocation still
denies access. A workspace approval is routing authority, not an OS sandbox.

### Refresh ChatGPT actions after an upgrade

An existing ChatGPT connection can still expose its earlier action set after
Gateway adds tools. Refresh requires a valid connection and permission to manage
it. For a directly connected custom MCP server, open its connection in
**ChatGPT Plugins → Refresh**, then confirm that `list_workspaces` and
`resolve_project` appear. See [OpenAI's direct-connection refresh procedure](https://developers.openai.com/plugins/deploy/connect-chatgpt#refresh-metadata).

For a workspace-published app, an admin/owner must review and publish the update.
Use **Workspace settings → Apps → ⋯ → Action control → Refresh**, or the
publish-time **Configure Actions** control where available. New actions can be
disabled by default; enable the required actions before publishing. The retained
app settings are also reachable from **Admin Console → Plugins → Manage Legacy
Apps**. Ordinary members must ask their app manager. See [OpenAI's workspace
action-control guidance](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt).
Start a new chat and select the updated connection before testing again.

If `list_devices` works but `resolve_project` is absent, stop before preparing a
task. Compare the authenticated server `tools/list` response with ChatGPT's
enabled actions. Refreshing action metadata does not enroll a device, alter
workspace permission/budget ceilings or dispatch a task.

## Operate and recover

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

Use the repository-pinned Go compiler with `GOTOOLCHAIN=local` and
`GOWORK=off`. Build Gateway and the acceptance helper from the Gateway checkout:

```sh
go build -o /absolute/private/bin/gateway ./cmd/gateway
go build -tags=e2e -o /absolute/private/bin/gateway-e2e-fixture ./internal/e2e
```

In the matching Native candidate checkout, build the Native pair together:

```sh
go build -o /absolute/private/native/bin/delegate ./cmd/delegate
go build -o /absolute/private/native/bin/delegate-run ./cmd/delegate-run
```

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
  --work-parent /absolute/private/acceptance --run-native
```

This scenario runs two local embedded connectors and three literal fixture
tasks, with a four-attempt safety cap and one active task at a time. It uses
no paid provider. A passing result reports `native_connect_passed` and
`cleanup_confirmed: true`; evidence stays in the reported private directory.
Unknown original process ownership blocks descendant cleanup and retains
resources. This does not verify browser login, desktop services, installed
providers, physical networks or Cloud clients; those need separate live checks.
