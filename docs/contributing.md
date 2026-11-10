# Contributing

Read [AGENTS](../AGENTS.md) for rules and [architecture](architecture.md) for
milestone scope. M0 is contracts, engineering scaffolding and harness adaptation;
future Delegate connector commands are not implemented Gateway behavior.

## Development setup

Use the exact compiler pin in [.go-version](../.go-version) and dependencies in
[go.mod](../go.mod). `GOTOOLCHAIN=local` prevents implicit compiler downloads.
`make tools` installs pinned repository tools; missing prerequisites must report
an actionable error. Python 3.12+ is required for repository validation.

Run focused affected checks while editing. `make check` is the complete gate:
formatting, vet, lint, race tests, build, vulnerability, harness and docs checks.
`make verify-harness` checks native role wiring, skill metadata/local references
and isolated acceptance/rejection fixtures. `make check-docs` checks documentation
local links and anchors; it does not execute documented commands. Read the [quality floor](../agents/_data/code-quality-floor.md)
for evidence limits. Unavailable checks remain unverified.

## Repository skills

Shared skills live in `skills/`; [AGENTS](../AGENTS.md#discovery-and-skills) is
the catalog used by Codex and Claude. Read only the applicable skill and linked
references. [Harness guide](harness.md) records source provenance and exclusions.
The validator checks wiring and bounded structural behavior, not an LLM's
judgment. Independent integrated reviewers examine actual use and evidence.

## Documentation completion

Reconcile affected README, guides, examples, skills and diagrams after behavior
checks and before independent review/PR. Record source-backed no-change reasons
where appropriate. Regenerate changed diagrams from their maintained source and
inspect readable rendered/exported output; link/checksum checks alone do not
prove semantic freshness or visual quality.

## Live acceptance

`make e2e-local` is reserved for built Gateway/connector and actual compatible
Delegate with a fixture provider. `make e2e-provider` requires explicit installed
provider/account and finite-budget authorization. `make e2e-external` requires
named authorized endpoints/devices/IdP. Blocked future targets must fail clearly;
no mock substitutes for required live acceptance. Current-host tests do not
prove macOS, another network or ChatGPT Cloud integration.
