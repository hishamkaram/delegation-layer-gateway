# Release assessment

## Remote Delegate candidate — 22 November 2026

Source metadata prepares Gateway **0.2.0** and Delegate **0.9.0**. Neither release
has been published. The Gateway candidate is deployed to the authorized test
server. Home's original registration now selects a reviewed, locally built
Native candidate; Office's original selection remains unchanged. Global
package installations were not replaced. The candidate removes
duplicate execution ceilings and adds scope-relative filesystem/provider discovery, explicit profile
migration and an installed-executable handoff.

**Not release-ready.** Compact registry-loss intent reconstruction and Gateway
continuation are implemented in the candidate. New path-based admission requires
the matching Native executable features and immutable binding; legacy
binding-absent routes fail closed. The local paired-process compact-dispatch
scenario passed with two connectors, exact accepted results, stable retries,
restart/reconnect and confirmed cleanup. It used a literal test provider;
installed-provider acceptance on Office and final integrated verification
remain incomplete.
Scoped Opus and native correction reviews do not replace the required final
integrated Sol/Opus reviews. New actual-process Linux filesystem evidence has its
own [recorded checkpoint](verification.md#november-21-remote-filesystem-candidate-checkpoint).
[Gateway CI](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/44998593189)
passed all three Linux/macOS and harness jobs at `57ac598`.
[Native CI](https://github.com/hishamkaram/delegation-layer/actions/runs/44996630923)
passed all 22 jobs at `d5208d35`, including its full macOS gate. Earlier failed
CI attempts remain recorded in the deployment checkpoint; the new pass does not
explain their causes. Home now selects the reviewed Native correction candidate.
Its original identity and credential survived the GUI-controlled installation
handoff and authenticated WSS reconnection. The composition and stdin EOF fixes
also passed focused Linux and actual macOS scratch tests.
Independent Sol and Opus reviews found no actionable P0/P1/P2 in those
corrections. Subsequent source review identified a P2 retirement case: an
unfinished upgrade can retire the resident that still owns its accepted
target's Wait. A regression reproduced the forbidden retirement attempt; its
guard is implemented in Native `845b1372` and passed focused race/static checks
and independent scoped review. Two valid completion crash tails retain their
canonical cleanup path. Native `db086178` implements the automatic GUI upgrade
adapter; 74 focused race-test cases, scoped static checks and independent native
review passed. Gateway CI at `3d5158f` passed all three jobs. Native CI
`45010946262` at `db086178` reported failures in the Linux cold-predecessor
fixture and macOS Gateway-upgrade tests; their causes are under investigation.
Those integrated reviews initially disagreed. Cross-review confirmed the
retry/retarget lockout, pre-claim recovery, lost Native review guidance and a
shared missing-helper retirement gap; both reviewers withdrew an unsupported
re-enrollment counterexample and corrected their proposed crash ordering.
Native `64aa9e79` implements the corrections. Independent native source review
found no outstanding P0–P3 in that correction delta. The affected command/service
race scope passed 134 cases against the pinned SDK with `GOWORK=off`; the
remaining App scope passed 22 cases. Scoped static and documentation checks
passed. Sol subsequently identified a terminal-publication race that Opus and
the native reviewer had missed; both confirmed its concrete interleaving.
Native `c6384e0c` corrects that race and the adjacent concurrent-proof case.
Both deterministic regressions now pass, along with 71 affected service cases
and 24 dependent command cases against the public SDK pin. The same follow-up
corrects a generic blocker label without changing Native's refusal/action.
Independent native review found no further findings in the four-file follow-up.
Sol and Opus subsequently reviewed that four-file correction with zero known
P0–P3 findings. The final-test counterfactual reproduced both expected failures
against the old code while conservative controls passed.
Gateway CI at `545307a` passed all three jobs. Native's earlier macOS gate
failed its App composition fixture: an actual child could not consume the
fixture's in-memory SDK profile. Native `84102f26` makes the existing injected
GUI control available to both parent and child; the default production Manager
and its validation remain unchanged. The corrected fixture exercises the public
App child and real Native lifecycle, with only the OS edge simulated. Both GUI
and Linux direct routes passed, along with the other-profile refusal, 111 fast
consumer/guard cases and scoped static checks. Independent Sol and Opus reviews
found no P0–P3 in that four-file correction. Its full Native CI
[45022132280](https://github.com/hishamkaram/delegation-layer/actions/runs/45022132280)
passed twenty jobs but failed the macOS cold-predecessor upgrade test. The retained
failure does not identify its private error cause. Native `4bc39ef8` corrects a
separate shutdown-acknowledgement counterexample: a successful graceful command
can precede daemon exit, so reconciliation must retain that success rather than
resend it just because the endpoint still responds. The regression failed with
two shutdown Starts before the fix and passed afterward. The correction retains
the existing exact-operation, Wait and process-absence closure requirements.
Thirty-five focused race cases passed, including ordinary/legacy recovery,
publication faults and strict older-reader compatibility. The real public CLI
cold-upgrade test passed on Linux against the final source; scoped static and
documentation checks passed too. This does not establish the historical CI cause
or actual macOS behavior. Sol, Opus and the independent native reviewer found no
P0/P1/P2 in the correction. Opus identified a lost legacy-alias test partition;
Native `d18b9e44` restores it alongside the requested and acknowledged cases.
All three partitions passed with the race detector. Follow-up review and full CI
for that test correction were still pending at that checkpoint. Gateway CI
[45030213612](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/45030213612)
at `42bddbb2` passed all three jobs. Simulated OS evidence does not prove actual
launchctl behavior. Public commands, schemas and architecture ownership
did not change, so this internal correction needs no guide or diagram changes.
Subsequent Native CI
[45031237723](https://github.com/hishamkaram/delegation-layer/actions/runs/45031237723)
at `d18b9e44` passed eighteen jobs but failed both platform checks and their
dependent gates. The App fixture's current-output DTO lacked the new journal
field; Linux also exhausted an unsupported four-call test limit while Native
correctly reported the same predecessor Wait pending. These are distinct test
defects. Native `475fcc52` repairs the current-output DTO and bounds the cold-test
driver by its existing caller context, retaining exact-operation checks and
stopping on faults. The strict DTO repair passed all 24 affected top-level tests.
The driver regression failed specifically at the old four-call cap, then passed
alongside its negative controls. Final-name vet, lint and formatting passed.
The actual Linux public-CLI cold upgrade and shared Gateway composition also
passed: two top-level tests and six subtests, with the command joined and source
unchanged. Sol and Opus reported zero P0/P1/P2 findings. Sol identified a P3
privacy-oracle gap that Opus also noted: the test omitted the real per-attempt
projection. Native `f9f318bc` strengthens that single test. Reverting only that
projection's sanitization now makes it fail on the private canary. After exact
helper restoration, the focused race test and scoped static checks passed.
Sol, Opus and the independent native reviewer then reported zero P0–P3 findings
in these corrections. No runtime code, timeout, closure or strict-decoding
requirement changed. Native run
[45037268782](https://github.com/hishamkaram/delegation-layer/actions/runs/45037268782)
at `475fcc52` was deliberately cancelled as superseded after fifteen successful
jobs; cancellation is not a passing verdict. Final-head Native run
[45038346801](https://github.com/hishamkaram/delegation-layer/actions/runs/45038346801)
at `f9f318bc` remains in progress and must pass. Gateway CI
[45031243127](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/45031243127)
at `ed7b94d6` passed all three jobs.
The later Gateway run
[45037355670](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/45037355670)
at `4755f580` also passed all three jobs; it precedes the final test-only Native
pin update.
Actual automatic macOS adapter acceptance has not run. The `sdk-source-751a59e24f17` archive tag retains the immutable SDK
source used by Native's pinned pseudo-version before branch squash/deletion.
Current ChatGPT Cloud browsing passed. Two real Native Claude turns on Home
also passed exact-byte/hash verification and observed-session continuation.
They used the managed service's configured PATH in a natural Aqua context.
The operator subsequently reported a successful actual ChatGPT Cloud two-turn
Gateway test on Home, including exact bytes/hashes and both canonical terminal
closures. Root independently matched the stored correlation, descriptors and
closure observations. A later seven-call Cloud report also passed workspace,
directory, structural Git, requested-file and accepted-result reads. The operator
explicitly identified that client as ChatGPT. A separate Claude.ai report then
passed the same seven read-only tools and retrieved the exact existing
`FIRST_OK` result. Both client identities are operator-confirmed. These reports
test the existing Home service; they do not establish final-build upgrade,
fresh provider execution or OAuth refresh. This Cloud evidence is separate from
the Native proof. The final `d18b9e44` source built successfully on both Macs,
with verified unchanged source inventories and joined build/transport owners.
Those installations are staged only. The later four test-file changes do not
alter normal CLI build inputs; the candidates retain their `d18b9e44` provenance.
Office's scheduler remains running at the
operator's request; Home's handoff was deferred while CI corrections finish.
Office rollout, actual automatic GUI upgrade acceptance and seven actual elapsed days of
login/refresh acceptance remain outstanding. See the
[deployment checkpoint](verification.md#november-21-reviewed-candidate-deployment).
Home's current Claude authentication differs between Aqua and SSH despite the
same executable/config directory and no auth overrides. Two Cloud tasks were
rejected; their historical execution-context cause remains unverified. The later
GUI-controlled upgrade wrote a minimal service PATH. Supported service
uninstall/install/start restored the invoking user's provider PATH; all six
installed provider executable names then resolved. Routine-upgrade PATH
preservation and automatic GUI control are implemented; final integrated review
and actual-Mac proof remain outstanding.
There are no PR, merge or release claims for this candidate.

The sections below retain the earlier revisions and evidence; they do not
establish acceptance of the current working tree.

## Historical Native-connect release preparation — 14 November 2026

Source metadata prepares Gateway 0.1.0 and Delegate 0.6.0. This is version
preparation, not a published release or an installed-binary upgrade. Application
versions are separate from the unchanged MCP, WSS and stored-schema versions.
The integration PRs were squash-merged as Gateway `2ddbc01` and Native
`a33fb15`; Gateway tag `archive/pr-3-native-connect` and Native tag
`archive/pr-181-gateway-connect` retain the existing SDK and acceptance-source
pins. The SDK pseudo-version remains valid; there is no dependency on an
unpublished `v0.1.0` tag. The dated assessment below keeps its evidence scope and
historical cleanup limits.

## Recorded extension assessment

**Recorded Native-connect extension: not release-ready at this assessment.** That candidate added
owner enrollment and policy, schema-9 project-resolution state, wire-v2
workspace routing, targeted capabilities and the Native-owned embedded-service
path. Canonical path is the approved project identity; same-path replacement
is allowed. The directory-incarnation proposal is superseded. Native Linux
service-recovery and the later launch/error/root-projection corrections are
implemented and independently reviewed. Final scoped Sol, Opus5.5 high and
native reviews found no actionable source P0/P1/P2 in the inspected paths.
The local literal-fixture process scenario passed with exactly three tasks and
confirmed cleanup. The subsequent service-runner correction also passed native
Linux/macOS regression checks and actual public Linux onboarding, dynamic-project
selection and installed-Claude execution. Public headless login passed; Office's
browser auto-open was operator-reported; its running LaunchAgent and narrowed
workspace were independently observed. A Home
token/foreground test confirmed overlapping physical-device WSS connections,
then joined its original processes and revoked its temporary credential. Complete
final-source CI passed at Gateway `c9ac6cf` and Native `c74d79cd`:
[Gateway Linux/macOS/harness](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43587760410)
and [Native Linux/macOS and auxiliary checks](https://github.com/hishamkaram/delegation-layer/actions/runs/43585217054).
The reviewed Gateway correction was deployed, and the operator applied the
rebuilt Office pair through Native's supported Aqua service controls. Independent
receipt and WSS observations verified that update and same-credential reconnect.
An actual operator-reported ChatGPT Cloud read of the original rejected task
returned final nonretryable `result_unavailable`. A separate fresh probe then
retrieved exactly PONG; independent public Native status/collection corroborated
its committed four-byte descriptor, and Gateway metadata matched its terminal,
unreserved operation. Cloud result bytes and guarded closure were not separately
retrieved by Root. Home subsequently completed separate browser enrollment,
dynamic child-project resolution and installed-Claude Cloud execution through
its new managed service. Public Native observations corroborated its committed
four-byte PONG descriptor; Gateway metadata matched terminal, unreserved
delivery. Its earlier unsupported long-root setup was explicitly fenced and
retired without moving state. A later authentication-rejected task remains
rejected; only a deliberately new task after operator-performed login passed.
Home's operator-attested alternate-network reconnect passed same-credential
WSS and same-completed-result Cloud checks, followed by reconnect on the
restored original network. Its new-profile service stop/start and post-restart
same-task Cloud result retrieval also passed, with same-credential WSS
corroboration. These retain their stated operator/metadata provenance. The earlier
capacity refusal's cause is not established by the later passing checks.
Historical timeout descendant cleanup remains unresolved. Scoped reviews and
these live results are not global approval or a release verdict.
See [Native connect](native-connect.md) for the intended operator paths and
[verification](verification.md) for dated evidence.

**Historical MVP assessment:** before this extension, Root recorded engineering
acceptance complete within its documented scopes and ready for PR review. That
MVP had actual process, provider, physical-device and Cloud-client evidence,
and its recorded final scoped Sol, Opus5.5 high and native assessments found no
actionable P0/P1/P2 within their scope. Those results apply to the recorded MVP
revisions; they do not validate the new extension or its current working tree.
Historical P3 uncertainties remain retained without invented closure. Merge,
issue closure and release publication remain separate actions; the compatible
Delegate prerequisite must be integrated before a Gateway release.

## Extension acceptance status

- Complete configured gates and scoped independent code/correction reviews
  passed on the recorded Gateway and Native revisions. Later evidence-only
  documentation changes use the required docs/harness checks; unchanged runtime
  results are retained at their actual revisions.
- Login, headless approval, browserless enrollment, authorization/revocation,
  workspace routing and targeted-policy checks have distinct recorded fixture
  and live scopes in [verification](verification.md). No fixture is promoted to
  installed-provider or Cloud acceptance.
- Linux and Office Native user-service lifecycles have recorded controls and
  creator joins. Home has its own new-flow browser/service, dynamic-project and
  Cloud provider and alternate-network recovery evidence. Its new-profile
  service stop/start and post-restart completed-task reads passed.
  Other physical-network and client categories are not inferred from a
  successful PONG.
- Keep fixture, installed-provider, physical-device/network and Cloud-client
  results separate. Earlier MVP evidence supplies no automatic pass for the
  new enrollment, dynamic-project or service flows.
- Historical cleanup provenance and merged-commit/tag pin retention remain
  explicit obligations; no unsafe cleanup or branch deletion is implied.

## Design and ownership

The approved design remains [MCP over HTTPS plus outbound device mTLS
WSS](architecture.md). Gateway owns enrollment, authorization, routing,
correlation and metadata observability. Native owns its local profile, approved workspaces, legacy project pins
and embedded service; legacy connector aliases remain
supported. Registry owns immutable device ownership and live owner policy,
without duplicating that policy into project grants. The current candidate removes
duplicate execution ceilings. Delegate alone owns provider support, execution
permissions, budgets, defaults, task admission, execution,
supervision, cancellation and accepted outcomes. The Gateway is trusted with
plaintext; additional end-to-end encryption is deferred.

Device/project selection is explicit. Uncertain delivery retains the original
operation identity; it never authorizes an automatic replacement or device
switch. Existing SSH/TUI behavior retains Delegate's owners. Project grants
restrict routing and are not an OS sandbox.

The [engineering harness report](harness.md) records reused, adapted, excluded
and replaced practices, dependency validation and supported agents. Gateway
inherits engineering discipline without taking over Delegate execution.
Delegate changes remain in their dedicated worktree using its own harness.

## Historical MVP changes and review

- [Gateway PR #2](https://github.com/hishamkaram/delegation-layer-gateway/pull/2)
  contains the implementation, harness, protocols, tests and operations guidance.
  Production correction `7061511`, holder `ed04ad9` and additive proof commit
  `a8ad5f5` have separately recorded validation.
- [Delegate PR #179](https://github.com/hishamkaram/delegation-layer/pull/179)
  at `d24a2cc2` provides the guarded public connector and recovery contracts,
  same-binding runtime restart/replay, Darwin peer identity and continuation
  diagnostics. It includes the recorded upstream-main integration.
- Actual Sol, Opus5.5 high and native reviews inspected code and correction
  evidence. Inspected production findings are resolved through their recorded
  correction gates. The later Home installer missing-plist P2 and SDK capture
  P2 were reproduced, corrected and independently re-reviewed before activation.
  Four optional installer findings were also corrected. Scoped review is not
  proof of absent defects across every possible execution.

## Historical MVP verification

The [verification ledger](verification.md) retains commands, exact source scope,
failed attempts, corrections, environment and limitations. The following completed checks apply to the recorded MVP revisions, not the
Native-connect extension:

| Evidence | Result and scope |
| --- | --- |
| `make check` | Passed in418.979s: 421 Python tests/no skips, Go race, tagged SDK, format/vet/lint/build/vulnerability/harness/docs. All387 frozen inputs stayed unchanged. Go1.27.4, Python3.12.13, umask077, dedicated NativeD24. Later prose is not relabeled as this original invocation. |
| [Gateway CI](https://github.com/hishamkaram/delegation-layer-gateway/actions/runs/43417831904) | Exact `a8ad5f5`: harness and complete Linux/macOS gates passed. CI's pinned Native acceptance-helper source differs from the local D24 selection; this does not replace Native's own gates or live D24 proof. |
| [Delegate CI](https://github.com/hishamkaram/delegation-layer/actions/runs/43260668961) | Exact D24: all19 jobs passed, including native platform, infrastructure, SSH and distribution checks. |
| Local/two-Mac processes | Actual Gateway, connectors and Delegate; enrollment, selection, concurrent controlled tasks, results, cancellation, restart/reconnect and revocation, with recorded creator cleanup. |
| Installed Claude | Both physical Macs; accepted results and canonical closure. Home also passed Gateway restart during execution, stable-identity duplicate retry and requested cancellation. Both persistent connectors passed lifecycle/readiness and later installed-provider execution. |
| Actual Cloud clients | ChatGPT in an operator-selected workspace and Claude.ai each retrieved PONG. Native metadata/audit corroborate the exact operations; no raw Cloud transcript is retained. |
| Snapshot rollback | An actual older SQLite backup was restored during later Native work; correlation/result reconstruction, stale-preparation refusal and unattributed-work isolation passed, with four task closures/two root closures. |
| Network migration | Operator-controlled Office IP change and restoration, changed observed TCP-source IPv4, fresh same-credential WSS generation and independent retained-audit replay. Separate connections are operator-attested, not per-flow WAN packet attribution. |
| Resource/security boundaries | Actual stalled TLS/header/body expiry and capacity reuse, real-store/TLS authorization/revocation, bounded pools/results, metadata canaries, fixed metric labels and graceful current-owner joins. |

Controlled providers, installed providers, native platforms, physical networks
and Cloud clients are distinct categories. The 0/1/200-device fixtures establish
authorization/pagination behavior, not capacity for 200 physical devices.
Vulnerability scanning found no reachable/imported-package finding; three
module-only findings remain separately reported.

## Retained historical limits

The examples below are not an exhaustive replacement for the failed-run ledger
in [verification](verification.md). Root accepts these as disclosed P3
operational/provenance limits: the historical MVP acceptance did not require reconstructing
unavailable original Waits. Failed cleanup is never relabeled as successful.

| Subject | Established fact | Missing proof |
| --- | --- | --- |
| Historical outer launcher | Its selected connector/SSH children and controller have successful completion/cleanup receipts. | The original outer tool exit could not be recovered. This is launcher provenance, not an inferred child leak. |
| Older Home remote wrapper | Original local SSH Wait255 and later same-run connector-child Wait0 are retained. | Original remote Python-parent completion/current canonical disposition. Child completion does not prove parent completion. |
| Retained failed startup fixture | Exact protocol3 root/epoch is known; no tasks were dispatched, paths are retained and cleanup failure is explicit. | Canonical disposition of the accepted infrastructure-helper attempt and its original Wait; intent/no birth record alone cannot prove never-launched. |
| Earlier Native app-race watchdog | The old aggregate timeout and later independent CI success are both retained in the verification ledger. | Descendant/resource closure from that fatal-timeout run; later successful CI does not erase that uncertainty. |

No current task leak is established by these historical gaps, and no closure is
invented. A later clean run, empty socket, expired deadline or missing process
handle cannot repair an original Wait. No historical owned paths are removed
without disposition. A generic supervisor status response does not resolve the
incomplete infrastructure epoch. Retention and explicit failure reporting
satisfy the unresolved-resource disposition rule; no historical path deletion,
PID adoption, signal or fabricated completion is authorized by this assessment.

Reboot/logout survival, automatic crash restart with the tested
`KeepAlive=false`, direct child Mach-context proof and fleet-scale capacity are
unproved platform limits. Provider authentication may remain advertised as
`unknown` despite a separately successful real task.

Root accepts operator-attested network selection and Cloud-client provenance
at their documented evidence levels, with independently matched task/audit
metadata. Packet-path attribution and raw Cloud transcripts are not claimed.
The historical reviewed prose corrections clarify controller-reported remote joins
and preserve the older watchdog uncertainty; they do not change runtime code.

The [implementation issue](https://github.com/hishamkaram/delegation-layer-gateway/issues/1)
and both PRs distinguish completed work from these open obligations. Merge,
release and issue closure are separate actions; green CI alone authorizes none.
