# Candidate deployment

Implementation and acceptance are in progress. Check the current
[verification gates](verification.md) before deploying the candidate. Run the
Gateway and each connector as their own intended service account. Keep private
configuration, identity, audit and database files outside this public checkout.

## Gateway configuration

Create owned 0700 directories for the database, admin socket and audit output.
Initialize the database once and retain the returned `gateway_id`.

```sh
gateway init --database /absolute/private/state/gateway.sqlite
```

Save an owned regular 0600 JSON configuration. Replace the example hostname,
issuer, generated identity and absolute paths with your deployment values.

```json
{
  "gateway_id": "GENERATED_GATEWAY_ID",
  "public_url": "https://gateway.example.com",
  "public_address": "127.0.0.1:9443",
  "device_address": "0.0.0.0:8443",
  "tls": {
    "certificate": "/absolute/private/tls/fullchain.pem",
    "private_key": "/absolute/private/tls/server.key"
  },
  "device_ca": {
    "certificate": "/absolute/private/tls/device-ca.pem",
    "private_key": "/absolute/private/tls/device-ca.key"
  },
  "database": "/absolute/private/state/gateway.sqlite",
  "admin_socket": "/absolute/private/run/admin.sock",
  "audit_directory": "/absolute/private/audit",
  "identity": {
    "issuer": "https://TENANT.us.auth0.com/",
    "audience": "https://gateway.example.com/mcp",
    "jwks_url": "https://TENANT.us.auth0.com/.well-known/jwks.json"
  }
}
```

The public URL is an HTTPS origin without a path. The configured audience must
match issued access tokens exactly. Gateway validates issuer, audience,
signature, expiry and required scopes. OAuth client registration and the user's
interactive login belong to the MCP client and identity provider. Gateway's
resource-server configuration contains no OAuth client secret or session secret.

For Auth0, enable **Resource Parameter Compatibility Profile** and **Include
Issuer in Authorization Responses** under tenant **Settings > Advanced**.
The first maps an MCP client's `resource` parameter to the API audience when
`audience` is absent. The second supplies issuer identification for the OAuth
callback. See [Auth0's configuration guide](https://auth0.com/ai/docs/mcp/guides/resource-param-compatibility-profile).
Set the API Identifier to the exact resource identifier Gateway advertises.

Verify that issuer discovery advertises PKCE `S256`. Copy the exact callback
shown by ChatGPT's MCP connection management page into Auth0's application
allowlist. The stable callback depends on issuer-identification support; other
connections can use a callback-specific URL. Do not infer the callback from the
Gateway hostname. See [OpenAI's authentication requirements](https://developers.openai.com/plugins/build/auth).
Public discovery checks do not prove audience selection, application grants or
successful interactive authorization; verify those with the actual client.

The server certificate must cover the public hostname. Both listeners require
TLS 1.3. The separate device CA signs client credentials and stays under Gateway
custody. Protect its private key and the database together. The admin socket is
local and private. Route HTTPS through the [Nginx setup](nginx-setup.md) and make
the direct device listener reachable from authorized devices.

```sh
gateway serve --config /absolute/private/gateway.json
```

The foreground command prints its bound listeners after startup. Its owner must
retain the process and join shutdown. An exit code of `3` reports unconfirmed
cleanup. Preserve its resources and investigate before restarting ownership.

## Connector configuration

Install a compatible Delegate/runner pair using Delegate's own installation and
supervisor workflow. Inspect its public connector capabilities and pin the
actual selected root and project. Existing roots require Delegate's documented
connector cutover and recovery procedure.

```sh
delegate --root /absolute/delegate/state context inspect \
  --cwd /absolute/project --gateway-id GENERATED_GATEWAY_ID --json
```

Keep the returned raw root/project tokens inside connector configuration. Registry
registration uses their normalized `ctx1_` SHA-256 guards. Replacing a project
directory does not authorize replacing its pin.

```json
{
  "schema_version": 1,
  "gateway_id": "GENERATED_GATEWAY_ID",
  "expected_device_id": "device-1",
  "enrollment_url": "https://gateway.example.com/v1/enroll",
  "wss_url": "wss://gateway.example.com:8443/device",
  "trust_ca_file": "/absolute/private/server-ca-bundle.pem",
  "device_ca_file": "/absolute/private/device-ca.pem",
  "identity_directory": "/absolute/private/identity",
  "delegate_executable": "/absolute/installed/delegate",
  "temporary_directory": "/absolute/private/tmp",
  "projects": [
    {
      "alias": "project-1",
      "root": "/absolute/delegate/state",
      "directory": "/absolute/project",
      "root_token": "PINNED_RAW_ROOT_TOKEN",
      "project_token": "PINNED_RAW_PROJECT_TOKEN",
      "providers": [
        {
          "provider": "SELECTED_PROVIDER_ID",
          "models": ["SELECTED_MODEL_ID"],
          "efforts": [],
          "permissions": ["read-only"],
          "max_budget_seconds": 30,
          "native_model": true,
          "native_effort": true
        }
      ]
    }
  ]
}
```

Choose provider/model/effort values supported by the installed Delegate and
authorized account. The connector ceiling and Gateway grant must both permit
the request. This example grants a bounded read-only ceiling. It does not
authorize a paid workload.

The connector configuration and CA bundles require owned regular 0600 files.
Create its owned 0700 identity directory and existing temporary directory before
starting it. The two trust bundles have separate roles and are loaded once.
See [certificate trust and rotation](nginx-setup.md) for their constraints.

## Enrollment and authorization

Use `gateway admin --socket ABS --action ACTION --input-file ABS` with private
0600 JSON input files. On Gateway, perform these steps in order.

1. `register-device` with `device_id` and `name`.
2. `register-project` with `device_id`, `project_alias`, `root_guard` and
   `project_guard`.
3. `resolve-principal` with the authenticated user's exact `issuer` and `subject`.
   Retain the returned `principal_id`.
4. `put-grant` with that principal, device, alias, allowed `scopes`, `providers`,
   `permissions` and `max_budget_seconds`. Available scopes are
   `inventory:read`, `task:dispatch`, `task:read` and `task:cancel`.
5. `issue-enrollment-token` with `device_id`, `mode` set to `regular`, and
   `generation` set to `1` for a new device. Use `--output-file ABS` to create
   the private one-time enrollment response. Transfer it securely to the device.

```sh
gateway connector enroll --config /absolute/private/connector.json \
  --token-file /absolute/private/enrollment.json
gateway connector run --config /absolute/private/connector.json
```

On Gateway, advance `initialize-root` with the exact registered four-field root
input until ready. Existing namespaces require explicit recovery. Follow
[root initialization and recovery](recovery.md), including credential generation
changes after enrollment or restore. Reusing generation `1` cannot replace an
already issued credential.

Connect the MCP client to the public `/mcp` endpoint and complete its OAuth login.
Verify discovery, the selected device/project, execution readiness and each
operation through that client's actual transport. Device presence and completed
root initialization do not establish provider authentication. Record local,
real-provider, two-device/network and ChatGPT Cloud results separately.
