# Verification and delivery gates

No runtime, provider, cloud or release acceptance has been performed yet.
Passing harness validation is not system proof.

## Milestones

| ID | Work | State |
| --- | --- | --- |
| M0 | Gateway engineering harness, contracts, architecture and instructions | In progress |
| M1 | Public Delegate boundary in its dedicated worktree, own harness and PR | Investigation; production edits gated on M0 |
| M2 | Gateway registry, admin, OAuth, enrollment and grants | Pending |
| M3 | WSS connector, local ceilings and Delegate adapter | Pending |
| M4 | MCP orchestration and recovery across real processes | Pending |
| M5 | Integrated hardening, docs and independent code reviews | Pending |
| M6 | Live evidence matrix and release assessment | Pending |

Root owns integration and Git. Native implementers own bounded packages and
tests. Independent Sol and Opus 5.5 high-effort reviews examine each current
candidate, actual diff, contracts and evidence. Correct every known P0/P1/P2,
rerun invalidated checks and review corrections before opening a PR.

Delegate changes use a separate branch/worktree and its existing AGENTS, skills,
configured tools and mandatory checks. The original checkout remains untouched.
Gateway uses adapted generic practices; it does not replace Delegate's harness.

## Planned engineering commands

- `make check`: configured quality, race, build, vulnerability, harness and docs
  gates. Missing tools or an empty runtime selection are not a passing result.
- `make e2e-local`: built Gateway + connector + actual compatible Delegate with
  an explicitly controlled fixture provider.
- `make e2e-provider`: opt-in real installed-provider execution with authorized
  credentials and a finite approved workload budget.
- `make e2e-external`: named devices/networks, issuer and MCP clients.

The runtime/E2E commands are implementation deliverables, not evidence they
already exist or work. Delegate retains its own mandatory gates.

## Evidence categories

Record local protocol, actual loopback processes, simulated network faults,
real-provider execution, two physical devices/networks, actual ChatGPT Cloud and
another MCP client separately. One category never proves another. For each
receipt record commits/dirty inputs, versions, platform, exact command, result,
scope, timestamps, cleanup and limitations. Use dummy secrets in privacy tests.

Fault/race scenarios cover delayed/duplicate requests, lost ACKs, partial writes,
refusal conflicts, root/project substitution, legacy writers, restart, revocation,
restore with late old preparation, result corruption, control-slot retention,
resource limits, malformed/oversized/slow inputs, canary logging and shutdown.

## PR and release policy

Open separate Delegate prerequisite and Gateway PRs only when their scoped
implementation/docs/checks and independent reviews pass with no known unresolved
P0/P1/P2. Record dependencies and tested revisions. Never merge an unreviewed
interface or substitute Gateway checks for Delegate's requirements.

Current authorization permits current-host tests first. External infrastructure
and paid provider workloads require named environments and approved budgets.
Unavailable mandatory acceptance stays blocked, not waived or replaced by mocks.
Native Linux/macOS behavior needs native evidence on each host.

Update Issue #1 with real milestone/check/review results. Distinguish implemented,
verified, blocked and release-ready. Do not merge, release or close the issue
automatically because a PR exists or CI is green.
