# Candidate release assessment — 14 November 2026

**Current Native-connect extension: not release-ready.** The candidate adds
owner enrollment and policy, schema-9 project-resolution state, wire-v2
workspace routing, targeted capabilities and the Native-owned embedded-service
path. Canonical path is the approved project identity; same-path replacement
is allowed. The directory-incarnation proposal is superseded. Native Linux
service-recovery and the later launch/error/root-projection corrections are
implemented and independently reviewed. Final scoped Sol, Opus5.5 high and
native reviews found no actionable source P0/P1/P2 in the inspected paths.
The rebuilt final local literal-fixture process scenario passed with exactly
three tasks and confirmed cleanup. Complete current-revision gates and
extension-specific external acceptance remain incomplete; Office's earlier
platform race invocation failed and is being investigated. Historical timeout
descendant cleanup remains unresolved. Scoped reviews and fixture proof are
not global approval or a release verdict.
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

## Extension acceptance still required

- Run the complete configured gates on frozen integrated Gateway and Native
  extension sources, then review the actual code and correction evidence.
- Exercise OAuth device login, headless approval and browserless token redemption,
  owner-policy/revocation enforcement, explicit workspace resolution/replay,
  targeted capabilities and current local policy through CLI Start.
- Prove the Native-owned embedded user-service lifecycle and creator joins on
  the supported platforms, including retained identity after interruption.
- Keep fixture, installed-provider, physical-device/network and Cloud-client
  results separate. Earlier MVP evidence supplies no automatic pass for the
  new enrollment, dynamic-project or service flows.

## Design and ownership

The approved design remains [MCP over HTTPS plus outbound device mTLS
WSS](architecture.md). Gateway owns enrollment, authorization, routing,
correlation and metadata observability. Native owns its local profile, approved workspaces, immutable project pins,
embedded service and stricter local ceiling; legacy connector aliases remain
supported. Registry owns immutable device ownership and live owner policy,
without duplicating that policy into project grants. Delegate alone owns task admission, execution,
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
