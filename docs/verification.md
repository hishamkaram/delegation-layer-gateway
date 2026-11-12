# Verification and delivery gates

## November 12 current integration checkpoint

**Not release-ready.** The current production-source candidates are Gateway
`8610c6c` and Native `d24a2cc2`. Their respective
[Gateway CI](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43219879990)
and [Native CI](https://github.com/hishamkaram/delegation-layer/actions/runs/43260668961)
passed all 3 and all 19 jobs respectively. Native includes upstream `68e572a1` and
uses its own harness in a dedicated integration worktree. Later operational
acceptance results below do not replace or broaden those CI results.

| Evidence category | Observed result | Scope and remaining proof |
| --- | --- | --- |
| Current local real-process fixtures | Passed in 154.896s with creator cleanup and original command joins confirmed. | Gateway, Native, Pueue and SDK processes are real; the provider is a controlled fixture. |
| Current two-Mac fixtures | Passed in 152.661s: four tasks, explicit routing and denials, result verification, overlap, cancellation, Gateway restart, reconnection and revocation. Both SSH owners and fourteen remote children joined. | Two physical devices are proved. Client response loss was simulated. Installed-provider recovery and independent underlying networks are separate evidence categories. |
| Home Native transition | The authorized isolated root completed bundled-pair migration, exact predecessor closure, same-binding runtime restart and completed same-reference replay. Root/project identities were preserved; original commands joined. | Default installations and provider accounts were preserved. Office's selected-state transition remains open. |
| Home installed Claude | One new read-only, 60-second/max-one task through authenticated public MCP produced a verified accepted 60-byte result. Canonical execution closure, successful native worker Wait and controller cleanup were confirmed. | This proves the installed provider on Home through the SDK client. It does not prove Office, ChatGPT Cloud task execution or provider fault recovery. |
| Real-provider cancellation | A fresh corrected automated run passed: one dispatch, running provider activity, exact matched user cancellation, requested termination after 1.031443s, and qualified worker Wait 48.598422s before the deadline. All 9 SDK, 4 SSH and 4 remote Native children joined naturally; task and controller cleanup were confirmed. | The earlier automated command remains failed because its per-request annotation was absent. Its later same-task composite proof is separate from this fresh successful run. No failed task was replayed or assigned another cancellation identity. |
| Linux persistence | The original foreground process joined exit0 before the enabled user service started. Authenticated MCP passed. A controlled service stop reported normal exit0, followed by restart and another authenticated inventory check. | This is qualified systemd process-exit/readiness evidence. It does not establish Native task closure or Mac service behavior. |
| Cloud and Mac operation | Earlier actual ChatGPT Cloud OAuth, discovery and inventory worked. Both Mac service definitions passed installed plist validation. A fully joined read-only probe confirmed that Home's existing tmux server has the Background manager context. | Cloud task execution, Mac service activation/clean exit, Office installed-provider execution and distinct underlying networks remain unverified. Home's tmux probe correctly refused GUI qualification; working Claude execution does not establish the GUI manager namespace. |

The cancellation failure exposed a sequencing error in the private acceptance
checker. Native's guardian owns lifetime termination and worker-Wait evidence.
Its per-request stop annotation has a separate maintenance writer. Passive
helper reads and guarded Gateway status do not materialize that annotation.
Ordinary Native status can do so after its ended-row, identity and closure
checks; it is maintenance-capable. A successful status observation may also
carry domain guidance such as `task_interrupted`, so an operational error must
be distinguished from that guidance. The subsequent strict helper proof keeps
the original request ID, user cause, requested termination, qualified Wait and
before-deadline timestamp checks. See Native's
[annotation writer](https://github.com/hishamkaram/delegation-layer/blob/d24a2cc2d568d1327c58e6520f6e48fb50d0606a/internal/tasklifecycle/stop_observation.go#L52)
and [status projection](https://github.com/hishamkaram/delegation-layer/blob/d24a2cc2d568d1327c58e6520f6e48fb50d0606a/internal/app/task_observation_projection.go#L47).

Independent correction reviews closed the inspected observer-locator,
timestamp-precision, cleanup-order and annotation-sequence findings. The
corrected remote projection was also verified on the same already-closed task
before the fresh cancellation run. Those scoped verdicts are not whole-system
or release approval. GUI service startup and exit qualification remain open.

Earlier failed builds, placement checks, provider attempts and cleanup gaps
remain retained. In particular, an earlier connector controller's exact children
have closure proof while its historical remote parent Wait remains unverified.
Later clean owners do not close that historical gap. No original failed
provider task was replayed, and no failed record was replaced with a pass.

The dated sections below retain their original revision and evidence scope.
Current status and open acceptance gates are also tracked in
[Issue #1](https://github.com/hishamkaram/delegation-layer-gateway/issues/1),
[Gateway PR #2](https://github.com/hishamkaram/delegation-layer-gateway/pull/2)
and [Native PR #179](https://github.com/hishamkaram/delegation-layer/pull/179).
The existing diagrams retain the same execution, routing and persistence
owners; these operational checks add no task-state authority or topology.

## Earlier November 12 upstream integration checkpoint

The dedicated Native integration worktree now includes upstream main
`68e572a1` ([PR #180](https://github.com/hishamkaram/delegation-layer/pull/180)).
That change adds versioned provider authentication diagnostics and scheduler
repairs. Gateway's acceptance capture retains only the closed diagnostic
values `provider_output_rejected`, `collect` and
`run_native_provider_login`; arbitrary messages, paths and credentials remain
excluded. The eight capture tests and configured Ruff checks passed.

Read-only checks of the same installed Claude CLI on the home Mac reported
logged out under SSH and logged in under its existing tmux context, including
when using the same saved environment values. This establishes a native process
context dependency. The exact macOS authentication mechanism is unverified;
the upstream diagnostic change does not repair that execution context.

The Native runtime-restart repair remains under integration review and testing.
Its focused regressions are not a completed platform gate or live provider
proof. The original rejected provider attempt remains rejected and will not be
replayed. A new, explicitly selected home-device request must produce a verified
accepted result before installed-provider acceptance can be claimed. Existing
Mac installations and provider credentials remain unchanged at this checkpoint.

The dated evidence below retains its original scope and revision. None of the
upstream merge, diagnostic tests or read-only authentication checks establishes
successful provider execution through ChatGPT Cloud.

## Reconnect retirement correction

A required Go race run failed while waiting for a second device generation.
Bounded failure diagnostics later reproduced the failure after successful TLS
and WebSocket upgrade, before routing reconciliation. The precise terminal
close error in those runs remains unverified.

A separate deterministic regression uses an actual enrolled TLS/WebSocket
connection whose TCP close completes and reports an injected diagnostic.
Transport's `Client.Close` joins its session before returning that diagnostic.
Connector previously returned from its fence without retiring the old socket;
every later census retried the same retained error. The regression failed at
the second census before the correction. Connector now joins the old intake
and retires its socket before reporting the initial cleanup error. A fresh
census can proceed; the original transport diagnostic is preserved.

The complete affected-package race command passed after this correction:

```sh
go test -race -count=1 -timeout=30m ./internal/connector ./internal/deviceruntime -v
```

Package durations were **47.243s** and **24.769s**. The real-TCP regression and
the regular/recovery-only reconnect checks passed, including authoritative ACK
readiness after reconnection. Scoped lint reported zero issues.

The fresh complete `make check` then passed in **727.275 seconds**, with pinned
Go 1.27.4, `GOTOOLCHAIN=local`, `GOMAXPROCS=4`, `GOFLAGS=-p=4` and the dedicated
Native contract worktree selected explicitly. This includes 398 Python tests,
harness/docs checks, formatting, vet, both lint scopes, all Go race packages,
the tagged MCP helper, build and vulnerability analysis. The scan found zero
affected or imported-package vulnerabilities and three module-only findings
outside reachable code. These are current local Linux results, not final-head
CI, native macOS or live provider acceptance.

Actual Sol and Opus correction reviews found no P0/P1/P2 in their inspected
Gateway scope. Opus noted optional coverage/diagnostic improvements, including
a combined live-intake/close-error case that the new regression does not
exercise. Earlier failed runs remain failed; the current Native shutdown
recovery correction and complete-system live proof remain separate open gates.

## Current live checkpoint and write-lifetime repair

On November 11, actual ChatGPT Cloud authentication, tool discovery and device
inventory succeeded. The client displayed both registered devices as offline
and not ready; Gateway audit recorded the matching inventory response at
`2026-11-11T18:38:29Z`. This establishes Cloud inventory only. No Cloud provider
request was demonstrated.

Both physical Macs enrolled real device credentials against the retained live
registry, using separate authorized Native test roots. Enrollment required
correcting the operator's device CA validity: a 30-day CA could not issue the
configured 30-day leaf. The same CA key/subject and original enrollment intent
were retained; no registry reset or replacement device identity was used.

On November 12, a second client using the official Go MCP SDK authenticated
through system-trusted public HTTPS and Auth0. It saw zero devices before its
explicit grants and exactly two afterward. Revoking that dedicated test
principal caused HTTP 401; restoring it permitted authenticated inventory again.
The original ChatGPT principal was unchanged. These checks launched no provider
tasks. Separate device-listener reachability, readiness, installed-provider
execution and different underlying networks remain unverified at this checkpoint.

The [CI run for `107c948`](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43077815209)
passed Linux and harness jobs but failed a macOS recovery test with
`device_offline`. Investigation found a separate concrete transport lifetime
defect: a peer reply could release `Reservation.Await` before the originating
WebSocket write returned. Cancelling the caller afterward could close that
connection. A real TLS/WebSocket regression reproduced premature completion on
the old implementation. The repair joins the write before returning a completed
response and preserves cancellation and session-teardown precedence. Its exact
role in that CI failure remains unverified.

Five focused transport race cases passed in **11.502 seconds** including the
runner. The instance lease tests passed under both `umask 077` and `022`. Their
invalid-permission fixture now explicitly sets 0644 before rejection, then 0600
before the independent symlink check; production permission rules are unchanged.
An integrated Go run retained a failure from that fixture before its correction.
All other race packages passed there with unchanged production inputs. The
current remaining Go targets passed in **112.533 seconds**:

```sh
GOMAXPROCS=4 GOFLAGS=-p=2 make fmt-check vet lint test-e2e-helper build vuln
```

This is composite local evidence, not a fresh successful `make check`. Both lint
scopes reported zero issues and tagged vulnerability analysis reported no
affected or imported-package vulnerabilities. Fresh final-head native-platform
CI and live acceptance remain required.

The new [connector hold controller](remote-fixtures.md#already-enrolled-connector-hold)
has separate source-backed review and fault tests. Independent review found
lost account environment, sibling cleanup skipped after stdin-close failure,
and potentially blocking controller stdout. All three paths were corrected.
The affected 173-test invocation retained one failure and two errors: a missing
test interruption owner and two wall-time failures. The fixture was corrected;
all three exact cases then passed in **9.124 seconds** with timing assertions
unchanged. A final publication-watchdog scope correction passed its focused
case in **3.717 seconds**. Further correction tests cover bidirectional bootstrap
mode agreement, final receipt attempts after observation/release faults and
bounded Native Wait after poll/signal faults. All eight focused cases passed in
**10.756 seconds** after source-backed failures were retained.

The final configured Python, Ruff, harness and documentation scope then passed
with unchanged inputs in **136.618 seconds**: **397 tests, zero skips**, taking
131.713 seconds for unittest itself:

```sh
DELEGATE_ACCEPTANCE_REPOSITORY=/absolute/dedicated/native-worktree \
  make test-tooling lint-python verify-harness check-docs
```

Native prerequisite source was `ad255598`. Eight negative harness fixtures and
all six diagram bindings passed. Actual Sol and Opus 5.5 correction reviews
closed the three cleanup findings and found no remaining P0/P1/P2 in the bounded
source scope. An inaccurate test comment about suppressed heartbeats was also
corrected to state the delayed-heartbeat and raw-write assumptions explicitly.
Fresh native CI remains a separate gate. Read-only SSH checks verified both provider
CLIs are visible in each Mac's actual account environment. Both Macs reached
the device TCP listener over the private overlay, while the configured public
port timed out. TLS/WSS, provider authentication and different WANs are not
established by those TCP and PATH checks.

The component and operation-safety diagrams keep their current owners and
connections. The write join and acceptance process owner add no execution or
persistence authority; no topology change requires regenerated artifacts.

## Public proxy discovery correction

An actual ChatGPT connection completed authentication but reported action
discovery failure. Its HTTP method, protocol version and response status remain
unverified. A focused regression independently reproduced HTTP 403 with the
documented TLS loopback upstream and public Host: the SDK's default loopback-host
heuristic conflicted with Gateway's existing exact Host/Origin guard. A separate
baseline request proved that a headerless two-item read-only batch executed two
tools under one HTTP admission. Neither experiment uniquely attributes the
reported Cloud failure.

The correction keeps TLS/Host/Origin checks in server composition, disables the
conflicting SDK heuristic, supports the three modern versions documented in
[architecture](architecture.md#connectivity-and-identity), and rejects batches
after authentication and HTTP rate admission. Seven focused race tests passed
in **14.935 seconds**, covering initialization/discovery, legacy headers, batch
rejection with zero tool executions, invalid non-JSON prefixes, and exact/overflow body limits. Their test
authentication is an opaque fixture token. A separate composed-server race test
passed in **9.062 seconds** using verified public-host TLS, a signed JWT and JWKS
retrieval. It also checks forbidden Host/Origin before key retrieval, absent and
invalid bearer tokens, and plaintext HTTP rejection.

The corrected local Go gate passed in **697.331 seconds** with Go 1.27.4,
`GOTOOLCHAIN=local`, `GOMAXPROCS=2` and `GOFLAGS=-p=1`:

```sh
make fmt-check vet lint test-race test-e2e-helper build vuln
```

Both lint scopes reported zero issues. The full race suite, tagged helper and
build passed. Vulnerability analysis found zero affected or imported-package
vulnerabilities; three module-level findings were outside the reachable code.
Only architecture/verification prose changed during that invocation; all Go,
test, fixture, dependency and compiler inputs were unchanged.

The first `make check` attempt failed on an unchecked type assertion in the new
test hook. That assertion was corrected. Its Python invocation also omitted the
Native harness prerequisite, so eight skips did not satisfy that gate. The
corrected invocation passed **363 tests without skips** in **70.580 seconds**
(71.085 seconds including the runner), with unchanged inputs:

```sh
DELEGATE_ACCEPTANCE_REPOSITORY="$PWD/.ci-native" make test-tooling
```

The earlier invocation's Ruff checks passed with unchanged Python/tool inputs.
Documentation/harness validation remains required on the final text.
Sol, Opus 5.5 and the independent native reviewer inspected the production
correction. Both named reviewers inspected the final fixes and reported no
remaining actionable P0–P3 within this correction's scope.

These were local engineering/protocol/security results. At that checkpoint,
native-platform CI, deployment and an actual ChatGPT retry remained separate
gates; the current checkpoint above records later evidence. The component/operation
diagrams retain the same owners and connections; no execution, persistence or
recovery boundary changes in this correction.

## Earlier integrated verification

The configured Linux `make check` passed in **439.666 seconds** before the
first PR CI run, with unchanged recorded inputs during that invocation.
Subsequent documentation/harness checks passed in **2.004 seconds** before
candidate `352d156` was published. The compiler was Go 1.27.4 with
`GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2` and the pinned Native
acceptance checkout. The full-gate command was:

```sh
DELEGATE_ACCEPTANCE_REPOSITORY="$PWD/.ci-native" GOFLAGS=-p=2 make check
```

It executed **338 Python tests without skips**, pinned Ruff, harness rejection
fixtures, six diagram bindings, formatting, both Go vet/lint scopes, the full
Go race suite, tagged MCP helper race tests, build and tagged vulnerability
analysis. Both Go lint scopes reported zero issues. The compiler was selected
explicitly on `PATH` with matching `GOROOT`; an ambient compiler is not proof.

The first [Gateway PR CI run](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43045202667)
passed its harness and Linux runtime jobs, but failed the macOS harness self-test
before runtime checks. Temporary paths used lexical `/var/...` while resolved
references used physical `/private/var/...`; valid links were falsely rejected.
The correction canonicalizes repository and temporary fixture roots and retains
physical source/destination containment. Four added tests reproduce the alias
case and reject external sources and targets. All eight original negative
fixtures remain. After that change, the invalidated Python/docs scope
`make test-tooling lint-python verify-harness check-docs` passed in **79.887
seconds**, including **342 tests without skips** in 70.709 seconds. Go, module,
compiler, build and runtime fixture inputs were unchanged and their prior results
are retained. A subsequent explicit canonical-root precondition adds one focused
regression; all five harness tests passed in 1.211 seconds, with the eight
negative fixtures and docs/binding checks still passing. That fifth test was not
part of the earlier 342-test invocation. The corrected native macOS result is a
separate CI gate; see the
[PR checks](https://github.com/hishamkaram/delegation-layer-gateway/pull/2/checks).
The earlier Linux gate alone does not establish that portability correction.

The [second CI run](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43048606085)
again passed Linux. macOS passed the repaired validator, then reported 14 Python
failures, 33 errors and three skips across 343 tests. Valid test fixtures still
supplied lexical temporary paths to strict canonical-path contracts. Their
creators now canonicalize valid roots before deriving configs, receipts,
manifests and preferred bundles. Deliberate invalid aliases and all identity,
mutation and finite-deadline rejection assertions remain unchanged. Production
path validation was not relaxed. Three additional regressions reproduce the
alias-parent cases with real filesystem symlinks on Linux.

That run also exposed a channel test's throughput assumption: a finite 8 MiB
producer was expected to drain within a five-second join. The log established
join expiry and unverified cleanup, not a stalled production drain. The repaired
fixture uses 131,076 bytes and requires at least three positive bounded drains,
continued capture after the protocol fault, exact byte totals, EOF and natural
Wait with exit zero. A separate parser boundary accepts exactly 4 MiB of valid
frames and rejects byte 4,194,305 as `output_byte_limit`. No production pump,
Native receipt, timeout or assertion was weakened.

After those test-only corrections, all **347 Python tests passed without skips**
under an actual symlinked temporary parent on Linux in **35.470 seconds**
(**36.375 seconds** including the controlled runner). Native's maintained
directory owner confirmed cleanup of that run. Ruff/harness/docs and all six
bindings then passed in **2.515 seconds**. This is integrated alias-path and
bounded-drain evidence; corrected native macOS CI remains a separate gate.

The [third CI run](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43053460392)
passed Linux and the harness job. macOS ran 347 Python tests in 21.761 seconds
and reported two errors in diagram-renderer descendant cleanup and three skips.
The earlier path/channel failures did not recur. Process-group permission denial
(`EPERM`) escaped the renderer cleanup and its test finalizers. This run remains
failed; it did not reach the macOS Go checks. The nonverbose summary does not
identify the skipped cases, so their identities are not asserted here.

The renderer correction retains the direct child unreaped until the final
process-group signal. Linux uses nonreaping `waitid`; Darwin uses kqueue with
explicit fast-exit registration handling. The standalone contributor process
owns the SIGCHLD policy, captures through private temporary files, and enters
cleanup once. A separate five-second cleanup deadline includes TERM, the
one-second grace, KILL, exact Wait and passive group-absence observation. The
uniform grace adds about one second per command, including normal exit. Group
mutation is forbidden after Wait, group ESRCH or identity loss. A prior EPERM
is resolved only by exact Wait plus ESRCH; persistent permission denial remains
unknown closure. This does not contain descendants deliberately escaping with
`setsid`, and changes no Gateway or Delegate task ownership.

The focused command passed **25 tests in 11.226 seconds** on Linux:

```sh
PYTHONPATH="$PWD/scripts" python3 -m unittest scripts/test_render_diagrams.py -v
```

The same frozen source pair then passed all **25 tests without skips in 9.571
seconds** on an authorized physical Mac, Python 3.12.11 / Darwin 27.2. Its SSH
process returned zero and the test-owned directory cleanup was confirmed. This
includes real stubborn descendants, Start interruption, termination and text
behavior, alongside deterministic identity-loss/error/order regressions. This
Mac result is distinct from the separate GitHub macOS 15 gate.

The affected integrated command passed all **361 Python tests without skips in
66.108 seconds**, plus Ruff, harness and six diagram bindings in **73.718 seconds**
total:

```sh
DELEGATE_ACCEPTANCE_REPOSITORY="$PWD/.ci-native" GOFLAGS=-p=2 \
  make test-tooling lint-python verify-harness check-docs
```

Code, tests and fixtures stayed unchanged during that invocation; two documentation
files changed. The runtime result is retained for that unchanged source scope,
while documentation checks are rerun after prose reconciliation. The earlier Go
checks cover unchanged Go inputs. Fresh complete CI results belong to the
[PR checks](https://github.com/hishamkaram/delegation-layer-gateway/pull/2/checks).

After the failure-retention correction, the final focused module passed **27 tests
in 11.042 seconds** on Linux, then **27 tests without skips in 9.542 seconds** on
the same physical Mac with confirmed cleanup and SSH exit zero. The final
`make test-tooling lint-python` with the pinned Native source passed all **363
Python tests without skips in 58.540 seconds**, plus lint/format in **60.177
seconds** total. Its recorded inputs stayed unchanged and its actual Wait returned
zero. These results supersede the earlier 25/361-test scopes for the corrected
test file; the renderer helper stayed unchanged.

The [fourth CI run](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43062276506)
on `4355161` passed harness and Linux. macOS passed its 363-test Python invocation
in 31.560 seconds with three existing skips, both Go lint scopes with zero issues,
and then failed Go race tests in admin API, CLI and server fixtures. The CLI
errors showed Unix socket paths lengthened by `t.TempDir()` test names and the
ambient macOS temporary prefix. The shared server/admin fixture setup used the
same pattern. The run remains failed; the renderer failure did not recur.

The correction changes test fixtures only: one shared
`testsupport.PrivateSocketDirectory` creates a random mode-0700 directory under
physical `/tmp`, independently of test-name length and `TMPDIR`. Existing
listener/store joins run before successful directory removal. Failed tests retain
the directory and report its locator. Two shared fixture roots and nine CLI bind
roots use it. Insecure-parent, cancelled/missing-socket inputs and all existing
assertions remain unchanged; production socket validation is untouched. New
regressions prove the overlong-path counterexample, real short-path binding,
canonical/private location, success removal and retained evidence from an exactly
joined intentional-failure child that creates only ordinary files.

Focused Linux race results on Go 1.27.4 were admin API **9.343 seconds**, CLI
**8.621 seconds** and server **17.902 seconds**. The final testsupport race run
passed in **1.411 seconds**. Commands used `go test -race -count=1` for the
affected packages with `GOTOOLCHAIN=local`, `GOMAXPROCS=2` and `GOFLAGS=-p=2`.
Full `make fmt-check vet lint`, including both tagged-helper scopes, passed in
**12.989 seconds** with unchanged
recorded inputs. A preceding invocation failed in **42.014 seconds** on a new
test's shadowed error variable; renaming it fixed the cause without changing the
lint rule or assertion.

Actual Darwin arm64 execution then reproduced the original CLI fixture's
`bind: invalid argument` using its `4355161` test preimage. All four corrected
package binaries (testsupport, admin API, CLI and server) passed without skips.
All five child Waits completed (the preimage intentionally exited one), SSH Wait
returned zero, source inputs stayed unchanged and the owned directory cleanup
was confirmed. The remote cases took **6.038 seconds**, or **40.813 seconds**
including candidate transfer and SSH. These were owned Go 1.27.4 binaries built
on Linux for Darwin arm64 with `CGO_ENABLED=0`, then executed on the physical Mac
(Darwin 27.2). This proves native non-race execution, not a native compiler build
or the required GitHub macOS 15 race gate. Current CI results remain linked in the
PR checks.

The preceding final invocation failed in **56.921 seconds** on unchanged inputs:
one of 335 tests incorrectly assumed a timeout-test helper would remain alive
until an assertion after another child's Wait. Its three-second self-exit could
win that race. An isolated preimage counterexample reproduced the assertion
failure and observed natural exit 17. That separate observation does not supply
the original failed run's unrecorded exit code. The repair holds Native's release
gate through both Wait attempts, preserves the unresolved-owner and zero-signal
assertions, then releases and joins both children. The failed invocation remains
failed evidence; the passing invocation followed this concrete fixture repair.

The earlier 383.775-second gate remains historical evidence. Two Python files
changed during that earlier run, so it was followed by a scoped 322-test rerun;
it is superseded by the unchanged-input final invocation above.

Govulncheck reported zero reachable vulnerabilities and zero additional
vulnerabilities in imported packages. Its verbose module-only results were
[GO-2026-6866](https://pkg.go.dev/vuln/GO-2026-6866) and
[GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860) in `golang.org/x/net` HTML
rendering, and [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) in
`golang.org/x/crypto/openpgp`. Those affected packages are not imported by this
candidate according to that scan. This is scoped static analysis, not a claim
that all required modules are free of advisories or the system is defect-free.

The latest physical two-Mac fixture passed in **119.661 seconds**, with unchanged
inputs and confirmed cleanup. It adds simulated dispatch HTTP-response loss
before delivery to the MCP SDK, then proves the same-operation retry does not
create another execution. It also confirms a fresh matching verified-credential
registration rejection after explicit revoke. All 14 remote process waits and
two SSH waits completed naturally with exit zero. The response-discarding client
intentionally returned exit one; that is the injected loss signal, not a service
failure. Installed-provider, public HTTPS/Auth0, different-WAN and actual ChatGPT
Cloud acceptance remain unverified. Final named Sol/Opus correction reviews
closed their known findings in the inspected scope; no release readiness is
claimed.

The preceding response-loss run failed after **97.241 seconds** because its
assertion required a resolved delivery state while the original task was still
running. The actual Registry contract permits `possible_send/existing` then
`resolved/terminal`; identity checks and rejection of prepared, unknown, refused
and impossible pairs remain required before retry. The corrected test preserves
those negative cases and uses both legal running and terminal observations.
The failed run remains failed evidence with confirmed cleanup. The preceding
**114.132-second** run remains valid evidence for the fresh credential denial,
but did not inject HTTP-response loss.

## Final independent correction reviews

Actual Sol and Claude Opus 5.5 high-effort exact-session reviews examined the
integrated corrections and challenged their failure paths. Both independently
found one P2: observation-only recovery could cancel the original task after an
observation failure or interrupt. Explicit construction-time cancellation intent
now permits cleanup mutation only for the original provider run and explicit
`resume --cancel`. Failure and interruption regressions require zero observation
mutations; cancellation retries retain the original identities. Both named
reviewers and the independent security reviewer closed this finding.

The final named correction tasks were Sol
`e988fa4b5234c5906ea381dcb189d010` and Opus
`8b6584ea0615b9f682f9d57745239934`. Their committed payloads were read completely
after checking the returned path, regular-file type, byte length and SHA-256.
They accepted the lost-response legal-state correction, deterministic timeout
fixture, public prepare allowlist, idempotent Native import setup and the Native
caller-brief classification repair. Caller file-I/O failures match dispatch's
existing validation classification; the canonical and plugin guides document
that this does not imply malformed contents. The conservative summary-write gap
after lease release is documented and cannot establish missing closure proof.

The macOS root correction and explicit helper precondition subsequently received
exact-session correction reviews from Sol `f901200ba2ad5a4244edad7d14c13a54` and
Opus `c29c6157c960050d00b2bae5c683bc4e`. Both closed the precondition finding and
reported no current actionable P0/P1/P2 in that inspected correction. The
independent containment review also accepted the root/destination safeguards.

The subsequent six-file test-fixture correction received exact-session reviews
from Sol `a072722ac29e25ea61e5cf9d166a77a5` and Opus
`c5fb5a3664f2b2eeb61cbd26440cf4a4`. Both reviewed the six-file correction within their stated scopes and
reported no current actionable P0/P1/P2 in that correction. They confirmed that
invalid path cases remain invalid and the channel's independent byte, drain,
fault and cleanup oracles are preserved. Neither review executed the tests or
established corrected native macOS CI.

The renderer correction then received actual-code reviews from Sol
`9ddd9d3e46207cfdfcd98fff71e05800` and Opus
`5c87f3adf95f3b3d9fe8028711570330`, plus an independent native reviewer. Both
named reviewers closed the two renderer P2s and found no actionable P0/P1/P2 in
the frozen pair. Their full committed payloads were validated and read. Sol also
identified a lower-severity test failure path that deleted unresolved actor
markers; the subsequent test-only correction retains failed scopes for diagnosis.
Sol `7c12e0c3ba41e7bd7eee761ccc31dad7` and Opus
`1003e0a4ece01172b239a9c4bd5fcc8b` reviewed that actual correction and closed the
retention finding, with no actionable P0/P1/P2 in the delta. An independent native
review reached the same scoped conclusion. Root separately verified the final
27-test Mac and 363-test integrated receipts; reviewers did not execute them.

The Unix-socket fixture correction received actual-source reviews from Sol
`d5e3b801f48d3624c82ad9a5121eb8b3`, Opus
`4516025f05800e4bf7ef43cd7fa5289b` and an independent native reviewer. Both named
reviewers reported no actionable P0/P1/P2, inspected the new shared helper and
all six consumer files, and confirmed existing negative cases and cleanup joins
remain intact. They did not run the native Mac or Linux checks. Root validated
and read both full accepted review payloads.

Lower-severity limitations remain explicit: this standalone contributor helper
requires sole-waiter ownership; it does not defend against a competing process
waiter violating that precondition. Aggregated ordinary errors may print a
traceback rather than the single-error CLI message. The uniform grace cost is
accepted to preserve straightforward cleanup ordering. One failed fixture
finalizer may make a closure error the top-level exception while preserving its
primary assertion in Python's exception context; retained evidence is unaffected.
None of these verdicts establishes a new whole-system or external acceptance
result.

These are scoped source-review conclusions. Reviewers did not run the final
aggregate, inspect every descendant receipt or establish external acceptance.
Their verdicts do not imply zero defects. Root separately verified the actual
commands, process waits and retained evidence described here.

The diagram worker inspected 12 generated page/export captures across both
themes and two viewport sizes; Root additionally inspected two full-diagram
export captures. Both diagrams were reconciled against the production source
checkpoint `5e065e84`, including conditional absence-fencing semantics and the
Native prerequisite. Later acceptance-driver and caller-brief corrections do
not change the displayed state ownership or topology. The contributor renderer
cleanup repair also leaves the maintained diagram specifications and artifacts
unchanged, so regeneration would supply no changed system semantics. The binding
checks remain mandatory. Integrity checks passed;
visual inspection and source reconciliation are separate evidence.

## Local process fixture evidence

The latest local process run (Run 15) passed in 86.241 seconds on Go 1.27.4
with confirmed cleanup. It used actual Gateway and Delegate processes, two local
connectors and a controlled literal fixture. HTTPS/JWKS authentication, enrollment,
explicit device/project selection, accepted 36-byte result retrieval and digest
verification passed. Stable dispatch retries returned correlation metadata;
separate resolution established authoritative task observations.

The same retained FIFO observer, nonce, PID, task identity and execution count
survived an active-task Gateway stop with actual Wait and restart against the same
registry. Reconnection, resolution and duplicate dispatch did not create another
execution. Public cancellation established requested termination, an empty native
scope and actual worker Wait before the deadline while the fixture gate remained
held. Cancellation retry preserved its identity.

Explicit same-registry recovery completed: full-fleet routing coverage, inventory,
import, drain, reopen and finish. Early finish and regular enrollment were denied
during recovery. Four fixture attempts executed with a 30-second ceiling and at
most one active task; both roots had confirmed canonical cleanup. Earlier failed
runs remain failures with separate evidence and closure reports.

Run 15 used a frozen snapshot of maintained Native acceptance source, predating
the new borrowed-input port. It proves neither that port nor the physical-device
SSH controller. It also does not establish backup rollback, two physical devices,
separate underlying networks, installed-provider accounts or actual ChatGPT Cloud
acceptance. New nonloopback binding and remote staging/channel harness components
have focused regression evidence; physical execution remains a separate gate.

The Native core candidate used by these fixtures is committed at
`62b11d347dbd7d524f5f5322f3c9c85ecdb3a7a9`. A later independent CLI input-error
repair is committed at `ad2555987a49a1f5e5dcb58d9392c5aed251d322` in the same
dedicated worktree and PR. Its focused lifecycle/public-App regressions, lifecycle
race package and final documentation checks passed. Its full local app-package
race run failed the 30-minute aggregate watchdog at **1800.137 seconds**. The
last active test had run 45 seconds and its subtest eight seconds; the nonverbose
output does not identify all earlier serial costs or prove a deadlock in that
last test. Fatal timeout bypassed fixture cleanup, so descendant/resource closure
is unverified. No uncertain resource was removed or signaled, and the unchanged
suite was not retried. Separate exact-commit CI is recorded on the
[Native PR checks](https://github.com/hishamkaram/delegation-layer/pull/179/checks);
its result cannot erase the local failure or cleanup uncertainty. The complete
[Native CI run 43044064368](https://github.com/hishamkaram/delegation-layer/actions/runs/43044064368)
subsequently passed all 19 jobs on `ad255598`, including Linux/macOS gates and all
six distribution-install checks. Gateway CI now pins that reviewed revision.
The Native `scripts` tree is identical to `62b11d34`, so retained local Python
harness evidence uses the same source. The installed CLI was not replaced.
Independent Sol and Opus 5.5 reviews accepted the bounded
core corrections after source-backed challenges. The committed remote-harness
corrections also received scoped independent reviews; the normal physical-device execution path subsequently passed its
bounded fixture flow. No installed-provider or release verdict is implied.
The separate [Native prerequisite PR](https://github.com/hishamkaram/delegation-layer/pull/179) is open. Native CI passed and is recorded in
[PR run 42998412645](https://github.com/hishamkaram/delegation-layer/actions/runs/42998412645),
including Linux/macOS gates and all six distribution-install checks. The earlier
manual run omitted distribution jobs and is separate evidence.

## Milestones

| ID | Work | State |
| --- | --- | --- |
| M0 | Gateway engineering harness, contracts, architecture and instructions | Implemented; structural/workflow checks and source-backed review passed |
| M1 | Public Delegate boundary in its dedicated worktree, own harness and PR | [PR #179](https://github.com/hishamkaram/delegation-layer/pull/179) open; all 19 exact-head checks passed at `ad255598`; local App timeout and cleanup gap retained |
| M2 | Gateway registry, admin, OAuth, enrollment and grants | Implemented; real enrollment and public Auth0 SDK inventory/revocation verified; full live matrix open |
| M3 | WSS connector, local ceilings and Delegate adapter | Local and two-Mac fixture flows passed; installed-provider accounts remain open |
| M4 | MCP orchestration and recovery across real processes | Local recovery and physical restart/reconnect/dedupe/cancel/revocation passed; external proof open |
| M5 | Integrated hardening, docs and independent code reviews | Current write-lifetime/connector-harness corrections reviewed with no known P0/P1/P2; fresh native CI and live gates remain |
| M6 | Live evidence matrix and release assessment | Fixture, public SDK and Cloud inventory evidence recorded; provider execution and remaining live matrix unverified |

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
- `make e2e-external`: zero-task system-trusted HTTPS/SDK preflight for an
  expected issuer and two explicit device/project targets.

The local process harness passed its bounded fixture flow. The opt-in live
drivers and their recovery commands are documented in
[live acceptance](live-acceptance.md). Actual installed-provider and external
acceptance remain unverified. Delegate retains its own gates.

The complete configured Gateway gate passed on an earlier candidate on Go
1.27.4 in 1539.166 seconds. After subsequent Native-feature compatibility changes,
the then-current Go recipes `make fmt-check vet lint test-race build vuln` passed in
629.967 seconds with unchanged Go, module, compiler and tooling inputs. A preceding
invocation failed four test-function complexity checks; the tests were simplified
without weakening assertions and the invalidated checks were rerun.

An earlier CI-equivalent `make test-tooling lint-python check-docs verify-harness`
floor passed after the scheduling correction: all 260 tests executed with
no skips using the pinned Native acceptance source checkout, and pinned Ruff
passed. This includes the staging, correlated channel and controller corrections.
The formatter's ignored-dependency fix also passed all nine focused tooling tests
and an actual `make fmt-check` in 8.603 seconds. These are separate command results;
a failed aggregate invocation is not relabeled successful.

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
same-registry recovery flow also passed. Native launch-identity corrections have since received scoped race and source
review evidence. The broader live matrix remains open.

Record local protocol, actual loopback processes, simulated network faults,
real-provider execution, two physical devices/networks, actual ChatGPT Cloud and
another MCP client separately. One category never proves another. For each
receipt record commits/dirty inputs, versions, platform, exact command, result,
scope, timestamps, cleanup and limitations. Use dummy secrets in privacy tests.

Fault/race scenarios cover delayed/duplicate requests, lost ACKs, partial writes,
refusal conflicts, root/project substitution, legacy writers, restart, revocation,
restore with late old preparation, result corruption, control-slot retention,
resource limits, malformed/oversized/slow inputs, canary logging and shutdown.

## Physical-device checkpoint

Two configured SSH targets completed bounded authenticated identity probes and
reported distinct Darwin boot sessions. That establishes two running OS sessions,
not underlying network separation or hardware attestation. Source-built Darwin
candidates were transferred to private fixture directories; no installed provider
account was used.

The first target enrolled, connected over outbound WSS and appeared online in the
normal controller run. Root initialization was rejected, so no fixture task
was dispatched and the second target never started. The retained aggregate error
does not identify whether inspection or the subsequent registry transaction
failed; zero recovery rows alone cannot distinguish a rejected transaction from
a path that never entered it. The first peer's final receipt confirmed all seven owned child Waits
and its SSH Wait. The aggregate run remains failed because its conservative
cleanup report also included the unstarted second target. No successful task or
aggregate cleanup is inferred from that narrower closure evidence.

A subsequent explicitly selected, zero-task diagnostic completed in 25.792 seconds
with controller/SSH/Native Wait and confirmed cleanup. Native startup inspection
and a fresh project refresh each returned valid public context responses under
the private capture launcher. Capture adds a Python parent and redirects Native
output to regular files before forwarding it. This is diagnostic evidence only;
it does not resolve the normal-path failure or prove physical task execution.
The original failure's child output and failure stage were not captured. A
subsequent direct zero-task diagnostic reproduced a fresh project-refresh
failure in 24.802 seconds with actual Wait and confirmed cleanup. This narrows
that later failure to the direct inspection exchange, but does not establish
the original initialization failure's branch or its root cause.

A separate metadata-only diagnostic identified the refresh rejection as HTTP
503 `device_offline`, before any routed Native call. Source investigation found
that transport published session presence as online before its handshake was
complete, while reservations correctly refused that session. Online and routing
readiness now derive from the existing handshake-completion signal and closing
state. The regression holds a real TLS handshake before capabilities finish,
then releases it and checks online routing separately from execution readiness.
The full transport race suite passed in 158.344 seconds. Sol, Opus 5.5 and an
independent concurrency reviewer accepted the correction after inspecting its
source and regression.

The next normal two-target run completed both root initializations and executed
four literal-fixture attempts, two per target, with no concurrency or quota
rejections. Two accepted results passed byte/descriptor checks. Two retained
fixture tasks overlapped and survived an actual Gateway stop/Wait/restart with
the same registry, identities, leases and attempt counts. These are partial live
proofs; the aggregate run failed in 205.089 seconds before normal cancellation,
because its conservative local scheduling guard had expired. Cleanup established
canonical root closure, seven owned control/service child Waits per peer and both
SSH Waits, all with zero exits. No full scenario pass is inferred.

The schedule now prepares both tasks before either dispatch, anchors each local
guard before its own dispatch, and prioritizes each first cancellation after that
root's restart checks. Both canonical requested closures precede cancellation
retries and gate release. Task budgets remain 30 seconds, local guards remain
25 seconds, and all lease/restart checks remain. Synthetic clock regressions
reject the old setup-inclusive guard and a wrongly moved global guard; exact
send/acknowledgment boundaries reject for each task. The per-task-only run still failed at the second acknowledgment, in
133.481 seconds, with confirmed cleanup. Three independent post-restart public
phases now use pairs of existing MCP helper processes under Native's process
owner; admissions and cancellations remain sequential. Every known helper is
joined on errors, and responses are matched by request index and original task
binding. No task budget or proof step was removed.

The resulting normal two-target run passed in **143.045 seconds**, with unchanged
runtime source inputs and confirmed cleanup. It used the source-built Go 1.27.4
Gateway and Native revision `62b11d347dbd7d524f5f5322f3c9c85ecdb3a7a9`.
All four literal-fixture executions completed the expected flow: accepted results,
overlapping held tasks, actual Gateway stop/Wait/restart, reconnect, stable
resolve/retry/resolve, requested cancellation with empty scope and actual worker
Wait before Native deadlines while gates remained held, cancellation replay,
authorization visibility, metadata/audit canaries, shutdown and cleanup.
Both peers reported exactly two attempts with no quota/concurrency rejection;
all fourteen owned remote control/service child Waits and both SSH Waits exited
zero. This is fixture-only physical-device acceptance, not installed-provider,
underlying-network or actual ChatGPT Cloud proof. Public revocation visibility
does not prove a certificate-specific reconnect denial; that remains explicit
in the run summary.

The next aggregate Go gate failed an older server fixture that assumed client
Dial return meant server handshake completion. Its repeated focused check also
exposed an assumption that socket join implied immediate session-map retirement.
The corrected test waits for Hub readiness, checks absent or offline/non-routing
revoked sessions, and retains actual revoked-certificate reconnect denial.
Independent review then identified that a duplicate session could mask a
credential-rejection test unless retirement was observed first. A bounded wait
for actual map retirement now precedes the revoked-certificate Dial.
Focused race count 10 passed in 27.278 seconds; the full server race suite passed
in 15.306 seconds. Independent review accepted the correction. The failed aggregate
run remains failed; its later build and vulnerability targets did not execute.
That failed aggregate is separate from the later successful configured checks
recorded above.

At that earlier checkpoint, physical certificate-bound reconnect denial was
unverified: generic audit events could not attribute a fresh credential denial.
The registration-only observation and subsequent physical proof below close that
specific gap. Network separation, installed-provider accounts and actual ChatGPT
Cloud remain unverified.

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

## Fresh credential rejection after explicit revocation

A subsequent physical two-Mac fixture run passed in **114.132 seconds** with
unchanged tracked scenario inputs, four zero-cost fixture attempts and confirmed
cleanup. All fourteen remote control/service children and both SSH transports
had successful actual Wait receipts. It used newly built normal Linux/macOS
Gateway candidates and the tagged SDK helper, with Native source
`62b11d347dbd7d524f5f5322f3c9c85ecdb3a7a9`.

After all four operations closed, the controller read the current credential
identity through the protected admin API, persisted a private audit cursor and
explicitly revoked that device. It then observed a **new verified registration
rejected by Registry**, matching the frozen device/epoch/generation. The private
receipt identifies the exact audit segment, offset, record length and SHA-256.
Protected Recorder health was healthy before and after the observation.

This supplements the earlier public inventory/authorization revocation proof.
It does not identify unique certificate DER, establish an exclusive rejection
reason, prove client receipt of HTTP 403, or independently witness completion of
that audit event's fsync. The fixture owns the fresh private registry and sole
administrative writer; same-reference connector renewal remains allowed.
Installed-provider, multi-WAN and actual ChatGPT Cloud acceptance remain
unverified.

The run preceded two subsequently identified test-loader origin-check fixes.
Those fixes reject a foreign cached parent search path and foreign
`acceptance.py` providers before import. They do not change the tested Gateway
binaries or the fresh registration/Registry-denial behavior; their own regression
and source-selection validation must be assessed separately.
