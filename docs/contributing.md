# Contributing

Read [AGENTS](../AGENTS.md) for rules and [architecture](architecture.md) for
milestone scope. The connector depends on the separately reviewed Delegate
prerequisite candidate and validates the selected executable's public capabilities.

## Development setup

Use the exact compiler pin in [.go-version](../.go-version) and dependencies in
[go.mod](../go.mod). `GOTOOLCHAIN=local` prevents implicit compiler downloads.
`make tools` installs pinned repository tools; missing prerequisites must report
an actionable error. Python 3.12+ is required for repository validation.

Run focused affected checks while editing. `make check` is the complete gate:
formatting, vet, lint, race tests, build, vulnerability, harness and docs checks.
The gate also runs vet, lint and `make test-e2e-helper` for the tagged SDK client,
which the default Go package traversal excludes.
`make verify-harness` checks native role wiring, skill metadata/local references
and isolated acceptance/rejection fixtures. `make check-docs` checks documentation
local links and anchors; it does not execute documented commands. Read the [quality floor](../agents/_data/code-quality-floor.md)
for evidence limits. Unavailable checks remain unverified.

The FIFO and bootstrap process tests reuse Native's maintained acceptance source.
For the full Python gate, set
`DELEGATE_ACCEPTANCE_REPOSITORY=/absolute/path/to/compatible/delegation-layer`.
Without it, Native-dependent cases report skips and supply no process proof.
CI checks out the immutable Native revision declared in its workflow into the
ignored `.ci-native` directory and sets that variable for every gate job.
This is a test-source dependency, not a bundled runtime or provider installation.

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

## Unix-socket fixtures

Unix-socket fixtures use `testsupport.PrivateSocketDirectory` so macOS endpoint
limits do not depend on test names or `TMPDIR`. Call it before registering
listener/store cleanups; their joins must finish before directory removal.
Failed tests retain private `gw-sock-*` evidence beneath physical `/tmp`; resolve
cleanup before manually removing it. Retained fixtures can contain test-only
keys, stores and token files, so keep their mode-0700 protection.

## Diagram regeneration

`scripts/render_diagrams.py` owns its contributor child processes and requires
main-thread execution with default SIGCHLD policy. It observes child exit without
reaping until group cleanup signals finish, then joins the child and checks group
absence within a finite deadline. Cleanup failures are explicit; permission denial
alone is never absence. Private file capture prevents an inherited pipe writer
from extending the join. Deliberately escaped process sessions are outside this
process-group guarantee. Failed actor-test scopes retain their markers and add
the locator to the error; remove retained evidence only after resolving cleanup.
This helper is separate from Gateway task execution.

## Live acceptance

`make e2e-local` is reserved for built Gateway/connector and actual compatible
Delegate with a fixture provider. `make e2e-provider` requires explicit installed
provider/account and finite-budget authorization. `make e2e-external` performs
zero-task HTTPS/SDK preflight for an authorized endpoint, issuer and two explicit
device/project targets. See [live acceptance](live-acceptance.md) for private
configuration, opt-in flags and same-identity recovery. Missing prerequisites
must fail clearly; no mock substitutes for required live acceptance. Host-local
checks alone do not prove another native platform, network or ChatGPT Cloud.

For the explicit two-target zero-cost fixture controller, configuration and
retention rules, see [remote fixture acceptance](remote-fixtures.md).
