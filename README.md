# Delegation Layer Gateway

A trusted, self-hosted gateway connecting remote MCP clients to explicitly selected
devices running [Delegation Layer](https://github.com/hishamkaram/delegation-layer).
Clients use MCP over HTTPS; device connectors initiate outbound WSS connections.

**Native connection improvements are under implementation.** The new
`delegate gateway connect` flow, browser/headless enrollment and explicit
workspace resolution have separate validation gates. Start with the
[deployment and Native connection guide](docs/native-connect.md). The MVP
evidence below describes the earlier implementation.

**MVP implementation and live acceptance passed within the recorded scopes.** Real process flows, installed-Claude
execution and persistent connectors passed on both Macs. Auth0-backed SDK,
ChatGPT Cloud and Claude.ai tasks passed; rollback, network reconnection,
cancellation and resource-expiry checks have separately recorded evidence.
Independent final assessments found no actionable P0/P1/P2 in their inspected
scope. Historical P3 uncertainties remain reported with their paths retained;
merge and release publication are separate. See the
[release assessment](docs/release-assessment.md) and
[evidence and remaining gates](docs/verification.md).

## Ownership and trust

Gateway owns device enrollment identity, authorization, connectivity, routing and
metadata observability. The identity provider authenticates users. Delegate alone
owns task admission, execution, supervision,
cancellation and accepted outcomes. Gateway does not run a second task engine.

The Gateway is trusted to see request and result plaintext. TLS protects both
network hops; this MVP does not provide confidentiality against its operator.
Users sharing a device account are trusted peers: selecting a project controls
routing, not operating-system isolation.

## Development

Read [contributing](docs/contributing.md), [architecture](docs/architecture.md),
[public contracts](docs/contracts.md) and [harness provenance](docs/harness.md).
Repository instructions live in [AGENTS.md](AGENTS.md).

The exact compiler is pinned by `.go-version`; `go.mod` states the language
minimum. Select that installed compiler explicitly and keep `GOTOOLCHAIN=local`.
Use `make verify-harness` for the harness and `make check` for the applicable
engineering gate. Runtime and live acceptance are separate; see
[verification](docs/verification.md).

Track delivery and evidence in [Issue #1](https://github.com/hishamkaram/delegation-layer-gateway/issues/1).

For this host's isolated reverse proxy setup, see [Nginx setup](docs/nginx-setup.md).
The helper does not start Gateway or establish live MCP acceptance.
Runtime configuration and enrollment are described in
[candidate deployment](docs/deployment.md).
Opt-in provider execution and zero-task HTTPS/SDK preflight are described in
[live acceptance](docs/live-acceptance.md).
