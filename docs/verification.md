# Verification and delivery gates

The latest local process run passed in 146.953 seconds with confirmed cleanup.
It used the actual Gateway, two local connectors and the source-built Delegate
candidate with a controlled literal fixture. HTTPS/JWKS authentication,
enrollment, explicit device/project selection, accepted 36-byte result retrieval,
descriptor verification, stable operation retry and private administrative
resolution passed. Public cancellation established requested termination, an
empty native scope and actual worker Wait before the task deadline while the
fixture gate remained held. Cancellation retry preserved its identity.

Explicit same-registry recovery also completed: full-fleet routing coverage,
inventory, import, drain, reopen and finish. Early finish and regular enrollment
were denied during recovery. Four fixture attempts executed, with no concurrency
or allocation-limit rejection; both roots had confirmed canonical cleanup.
The harness required a fresh execution counter and FIFO identity followed by the
maintained nonce/PID handshake before advancing past provider startup. Earlier
failed runs remain failures; their evidence was retained.

This run does not establish backup rollback or Gateway restart while a task
remains executing: its retained task was cancelled before restart. Installed
provider accounts, native two-device tests and actual ChatGPT Cloud acceptance
remain unverified. The Delegate candidate has unresolved independent-review
findings, so this passing controlled run is not a release verdict.

That completed process run used Go 1.27.3. The compiler has since been patched to
1.27.4 for the published `net/http` advisory GO-2026-6859; the patched build and
vulnerability checks passed. The current harness additionally retains one
validated FIFO observer across an active-task Gateway restart and operation
retry. Its regression and real-FIFO checks passed, but that new live scenario
has not run yet. Neither change retroactively upgrades the earlier run's scope.

## Milestones

| ID | Work | State |
| --- | --- | --- |
| M0 | Gateway engineering harness, contracts, architecture and instructions | In progress |
| M1 | Public Delegate boundary in its dedicated worktree, own harness and PR | Candidate implemented; complete mandatory gate remains open |
| M2 | Gateway registry, admin, OAuth, enrollment and grants | Implemented; recovery integration and final checks in progress |
| M3 | WSS connector, local ceilings and Delegate adapter | Local fixture process flow passed; native devices and provider accounts remain open |
| M4 | MCP orchestration and recovery across real processes | Local same-registry fixture flow passed; active-execution restart and external proof remain open |
| M5 | Integrated hardening, docs and independent code reviews | In progress; Native launch identity and recovery findings remain open |
| M6 | Live evidence matrix and release assessment | Pending |

Root owns integration and Git. Native implementers own bounded packages and
tests. Independent Sol and Opus 5.5 high-effort reviews examine each current
candidate, actual diff, contracts and evidence. Correct every known P0/P1/P2,
rerun invalidated checks and review corrections before opening a PR.

Delegate changes use a separate branch/worktree and its existing AGENTS, skills,
configured tools and mandatory checks. The original checkout remains untouched.
Gateway uses adapted generic practices; it does not replace Delegate's harness.

## Engineering commands

- `make check`: configured quality, race, build, vulnerability, harness and docs
  gates. Missing tools or an empty runtime selection are not a passing result.
- `make e2e-local`: built Gateway + connector + actual compatible Delegate with
  an explicitly controlled fixture provider.
- `make e2e-provider`: opt-in real installed-provider execution with authorized
  credentials and a finite approved workload budget.
- `make e2e-external`: named devices/networks, issuer and MCP clients.

The local process harness passed its bounded fixture flow. Provider and external
targets still fail explicitly pending their authorized environments and
implementation. Delegate retains its own gates.

The configured Gateway `make check` completed successfully on Go 1.27.4 in
1539.166 seconds: formatting, vet, lint, every Go race package, build and
vulnerability checks passed. No Go, module, compiler-pin or tooling inputs changed
during that run. Five Python harness files changed after its initial tooling
stage, so the complete harness/docs/tooling/Python targets were rerun on their
frozen inputs: all 151 tests executed with no skips, and Ruff passed.

An earlier aggregate Go run failed an obsolete recovery transport fixture. Its
test-only correction now checks initial denial, complete fleet coverage, exact
prior-control drain and joined reconnect before recovery-only Status. Production
readiness was unchanged. The failed run is retained separately from the later
passing invocation. Diagram binding checks establish artifact integrity, not
semantic freshness or perceptual review.

Run the local harness only when its native acceptance slot is available:

```sh
make e2e-local E2E_ARGS='--delegate-repository /absolute/delegate/source --delegate /absolute/candidate/delegate --delegate-run /absolute/candidate/delegate-run --pueue /absolute/tools/pueue --pueued /absolute/tools/pueued --run-native'
```

The target builds Gateway and the test-only TLS/JWKS/MCP helper. The caller
selects an existing adjacent Delegate/runner pair and supervisor executables;
the harness runs them in place. It uses two local connector processes, private
configuration and the maintained literal Pi fixture, bounded to four sequential
attempts with at most one active task and a 30-second task budget. It uses no
provider account or paid request. Its private summary records failures and
unconfirmed cleanup; retain those resources until their owner proves closure.
This does not establish two physical devices, separate networks or cloud-client
compatibility. The helper requires the explicit `e2e` build tag and is excluded
from ordinary production builds.

The default work parent is the operator's home directory. `--work-parent`
selects another existing parent. Delegate state must lie outside the selected
provider's writable roots. The literal Pi fixture includes temporary directories
among those roots, so placing this fixture's state under `/tmp` fails admission.
Delegate performs the authoritative placement check.

The fixture records attempts before applying its execution and concurrency
limits. Acceptance checks those attempt and rejection counts again after joined
cleanup. Foreground daemon shutdown has one concurrent observer that performs
the maintained process owner's actual Wait, allowing strict PID-absence checks
to complete. Cleanup uncertainty remains a failed acceptance result.

The harness also exercises explicit same-registry recovery with retained
attributed and imported unattributed work, bounded to the same four fixture
attempts. Its evidence must state whether that recovery completed. Actual backup
rollback requires a separate snapshot test. Optional `--capture-native` adds
private native-control receipts for diagnosis. That variant adds a Python parent
and delays native stdout, which requires a separate evidence classification.

## Evidence categories

Current-host evidence includes actual SQLite stores, SDK MCP HTTP requests,
strict TLS device transport, revocation and resource-boundary tests. These are
component/integration checks, not actual ChatGPT Cloud acceptance.

A source-built Delegate candidate has also run two sequential controlled Pi
fixture tasks with private child configuration and no network or paid provider
request. Public CLI checks covered an unchanged task identity on retry, accepted
result bytes and descriptor, canonical execution closure, known-spec controls
and rejection of conflicting specs, cancellation, and two-project canonical
inventory/reopen. Both owned foreground engines have native Wait/cleanup receipts.
Cancellation's first reply remained asynchronous; termination was established
separately by canonical closure and native evidence before the task deadline.
This does not prove complete Gateway/connector process wiring or compatibility
of another installed Delegate executable.

An earlier deliberately retained long-path startup fixture has an unresolved
cleanup classification. It is separate from those two completed process runs;
no task/provider launch was observed for that failed startup. It remains an open
verification obligation, not a successful cleanup result.

Gateway process testing also exposed and corrected a real enrollment trust-pool
defect. HTTPS/WSS server trust and issued device-certificate trust now use
separate operator-pinned CA pools. Scoped certificate, renewal, reconnect and
re-enrollment tests passed, and the subsequent process run enrolled both local
connectors. Earlier failed runs have separate closure reports. A later real run
exposed an administrative observation timestamp sampled after its validation
timestamp. One post-reply timestamp now serves both roles; an advancing-clock
regression failed before the fix and passed afterward, and the next live run
passed private administrative resolution.

An earlier run returned `pending` twice during active execution. Investigation
found mandatory refusal fencing before cancellation. Delegate's live worker
holds the lifetime exclusion needed by that fence, whereas guarded native
cancellation can persist a stop request for the active owner. The connector now
resolves complete matching existing work before fencing, and its cancellation
path avoids that exclusion. The subsequent live run confirmed requested
termination as described above. The original failing run did not capture native
control stdout, so its exact native error and exit code remain unverified.

Adversarial review also found that a native cancellation stop receipt could be
combined with a different canonical task observation. Missing/wrong native task
and root IDs now reject the stop receipt; regressions demonstrated false
termination before the guards and rejection afterward. The root-ID guard is
included in the latest passing local process run. Fixture-gate reuse and the
same-registry recovery flow also passed. This does not close the outstanding
Native launch-identity findings or broader live matrix.

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
