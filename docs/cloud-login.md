# Keep cloud connections usable for a week

Gateway is a stateless OAuth resource server. ChatGPT or Claude stores and
exchanges refresh tokens; Auth0 issues them. Gateway validates each access token
and current device authority. Increasing an HTTP timeout or accepting expired
JWTs cannot fix a missing refresh grant.

The candidate advertises `offline_access` as an acquisition hint. It does not
require that scope in a resource access token, store refresh tokens, or implement
an OAuth proxy. Existing valid task-scoped tokens remain valid until their own
expiry or revocation.

## Auth0 configuration

Apply these settings to the existing **cloud MCP application**, separately from
Native's **Delegate Device Login** application:

1. In **Applications → APIs → your Gateway API → Settings**, enable **Allow
   Offline Access**. Keep its identifier equal to the Gateway resource/audience.
2. In the cloud application's **Advanced Settings → Grant Types**, keep
   **Authorization Code** and enable **Refresh Token**. Keep PKCE `S256` and the
   actual cloud client's exact callback and token-endpoint authentication method.
3. In its refresh-token expiration settings, set both idle and maximum lifetime
   to at least **2,592,000 seconds (30 days)**. Preserve longer existing explicit
   choices. Idle lifetime cannot exceed maximum lifetime. Keep access tokens
   short-lived; these are refresh-family settings.
4. Preserve the application's current rotation policy until its real client
   refresh/retry behavior has been checked. Do not blindly toggle rotation or
   change reuse intervals to conceal a failed refresh.
5. The actual authorization request must request `offline_access` alongside the
   required Gateway scopes and correct resource/audience. API configuration alone
   does not request it. If the client exposes base scopes, include it there.

Auth0 fixes a refresh family's maximum lifetime when issued. Updating settings
does not extend that existing maximum. One deliberate reconnect/new grant may
therefore be needed during rollout; repeated daily reconnects are not the target
experience. See Auth0's [refresh issuance](https://auth0.com/docs/secure/tokens/refresh-tokens/get-refresh-tokens),
[expiration](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-expiration)
and [rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation)
documentation. The exact current tenant and cloud-client behavior still require
live verification; no tenant settings have been inferred from repository tests.

## Diagnose without copying credentials

Record the client, application ID, requested scope names, audience/resource,
issued/expiry times, relevant Auth0 event IDs and refresh exchange success/error
codes. Do not record bearer or refresh token values, authorization codes,
secrets, full HTTP headers, or raw provider output.

If a token expires during a tool call, keep its preparation/operation/task IDs.
After refresh, resolve the same operation. Refresh does not authorize a second
dispatch, a replacement task or a different device. A fresh token also cannot
restore a revoked owner policy or device credential.

## Acceptance evidence

Verify ChatGPT and Claude separately. Record a fresh grant and successful normal
access-token refresh, then verify return after **seven actual elapsed days**
without manual reauthentication, including an idle interval. Record fresh tool
discovery, the same device and a read-only request after returning. Test expired
JWT rejection and local revocation independently.

An accelerated clock test, a configured 30-day lifetime, local MCP success and
one successful cloud login do not prove a week of cloud-client usability.
Current candidate's seven-day live proof is **Unverified** and remains a PR gate.
