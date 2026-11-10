# Delegation Layer Gateway

A trusted, self-hosted gateway connecting remote MCP clients to explicitly selected
devices running [Delegation Layer](https://github.com/hishamkaram/delegation-layer).
Clients use MCP over HTTPS; device connectors initiate outbound WSS connections.

**Implementation is in progress.** The engineering harness and public Delegate
prerequisites come first. No Gateway execution, cloud compatibility, or release
readiness is claimed by this repository scaffold.

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
