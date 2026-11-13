# Two-target fixture acceptance

`scripts/e2e_remote.py` is an opt-in test controller for two explicitly selected
SSH targets running macOS on arm64. It runs source-built Gateway/Delegate
candidates and the maintained literal provider fixture. It does not invoke an
installed provider account or establish ChatGPT Cloud compatibility.

```sh
python3 scripts/e2e_remote.py --run-remote-fixtures --config /absolute/private/run.json
```

The exact version-1 JSON configuration contains `schema_version`, `gateway`,
`fixture_tool`, `delegate_repository`, `listen_ip`, `candidate_directory`,
`build_receipt`, `work_parent` and `peers`. Paths must be canonical absolute paths.
`peers` contains exactly two entries, each with `ssh_alias`, `expected_home`,
`expected_uid`, `pueue` and `pueued`. The aliases must already resolve through the
operator's SSH configuration and trusted host keys. Connections use direct TCP;
ProxyJump, ProxyCommand and forwarding are disabled. There is no device fallback,
interactive login, package installation or automatic host-key acceptance.

The local Gateway and helper executables must already exist. The private
candidate directory contains only the operator-owned Darwin build candidates
`gateway`, `delegate` and `delegate-run`. Its build receipt identifies the exact
root, `darwin/arm64`, three successful joined build commands and each owned output's
length/digest. Installed SSH, Python and Pueue executables are used in place;
they are not copied or fingerprinted. The Native source directory supplies the
maintained acceptance modules, including borrowed-input support.

`listen_ip` is the reachable local IPv4 address used for fixture HTTPS/JWKS and
device TLS listeners. The fixture helper issues certificates for that explicit
address. This is a private controlled-issuer test; it is separate from public
TLS/Auth0 deployment.

The controller transfers a frozen, allowlisted source/candidate manifest through
one fixed SSH loader. It records known run/stage/final-receipt locators before
starting SSH. Bootstrap checks the expected account, exclusive private staging,
file identities/content, exact directory membership and the shared transfer
deadline. Checks happen at handoff; they do not make later same-account file
access atomic. Ready is tentative until the peer initializes successfully.

The channel owns request correlation and stdin EOF. Each command has a contiguous
request ID and a matching response; old, future or unsolicited proof cannot
satisfy a fresh request. Native's maintained process owner performs every child
Start and actual Wait. The peer owns its remote connector, fixture resources and
canonical closure observations. There is no second task supervisor.

The scenario permits exactly two fixture attempts per target, four in total,
with a 30-second per-task budget and one active task per target. It checks explicit
selection, accepted-result bytes, overlapping retained fixture observations,
Gateway restart against the same registry, stable retries, canonical cancellation
before deadline and credential revocation after task closure. Both tasks are held
and prepared before either is dispatched. Each local cancellation guard starts
before its own dispatch. The three independent post-restart public observation
phases use pairs of existing MCP helpers; both helpers start before either Wait,
and all known handles are joined even on failure. Each device receives its first
cancel after its retained-lease proof. Both canonical closures are checked while gates remain held,
then the original cancellation IDs are retried before gate release. A missed
timing or cleanup condition fails acceptance; budgets are not extended to obtain
a pass.

The first target's short task injects one bounded client-side response loss:
the helper receives the successful HTTP response, closes its body, then discards
it before delivery to the MCP SDK. Before ordinary retry, resolution must identify
the original operation, task, device and cancellation identity, with either
`possible_send/existing` or `resolved/terminal`. Prepared, unknown, refused and
impossible observations fail the scenario. The ordinary retry and final attempt
counts must still prove one execution. This simulates lost client delivery; it
does not prove packet loss across different networks. The intentionally failing
helper has a fixed loss marker, empty stdout and a real joined exit receipt.

Stages and evidence remain retained even on success. A final resource receipt
alone does not prove the SSH child exited. Missing output, uncertain launch or
missing native Wait remains unconfirmed; the controller does not search for,
adopt, relaunch or kill a guessed remote owner. Protect the private configuration
and evidence, which include local paths and credentials.

Record target identity evidence separately before claiming two physical hosts.
Distinct SSH aliases alone do not prove distinct machines, and distinct private
network addresses do not prove different underlying networks. See the complete
[evidence categories and release gates](verification.md).

## Private Native diagnostics

Use `--diagnose-native-target CONFIGURED_ALIAS` with the same explicit run flag
and configuration to select exactly one configured target. Unknown aliases fail
before resources are created. This mode grants inventory access only, performs
one fresh project inspection and stops before root initialization or task
admission. Completion also requires zero fixture attempts and confirmed cleanup.

By default it reuses the existing private Native-capture launcher. The launcher adds a
Python parent and delays forwarding stdout until the Native child finishes.
Raw CLI captures remain private and can include context tokens and local paths.
This mode reports `diagnostic_native_capture`; its success neither fixes nor
proves the original direct execution path.

Add `--diagnose-native-direct` together with `--diagnose-native-target` to run
the same zero-task inspection through direct Native execution, without the
Python capture parent or raw CLI capture files. It reports the separate
`diagnostic_native_direct` evidence category and still requires zero attempts
and confirmed cleanup. The direct flag without a target fails before resource
creation. Neither diagnostic category proves the full two-target fixture flow,
installed-provider behavior, physical devices, multiple networks or cloud-client
acceptance. The normal two-target fixture mode is unchanged.

The transferred Native source includes its exact versioned Unicode folding data
file. An isolated staged-import regression checks this dependency without using
modules already cached in the test runner.

## Already-enrolled connector hold

`scripts/e2e_connector_hold.py` is a separate finite owner for one or two existing
connector configurations. It transfers allowlisted Python source and Native's
maintained process/directory owners, then starts the selected owned Gateway
candidate with fixed arguments `connector run --config ABS`. It does not enroll
devices, provision an issuer, create a Gateway, install programs or dispatch
tasks. Use [live acceptance](live-acceptance.md) separately for public HTTPS,
readiness and provider evidence.

Its private 0600 JSON configuration contains exactly `schema_version: 1`,
`delegate_repository`, `receipt_directory` and `targets`. The local receipt
directory must not exist. `targets` contains one or two entries, each with:

| Field | Required value |
| --- | --- |
| `ssh_alias` | An explicit configured SSH alias with trusted host keys |
| `expected_home`, `expected_uid` | The verified remote account home and UID |
| `run_id` | A new 16-character lowercase hexadecimal run identity |
| `gateway` | Absolute path to the already owned remote candidate |
| `config` | Absolute path to the existing owned 0600 connector JSON |
| `receipt_directory` | Exactly `EXPECTED_HOME/gh-RUN_ID`, initially absent |
| `hold_seconds` | Integer from 1 through 900 |
| `device_id`, `gateway_id` | Exact identities bound by that connector config |

Paths must be canonical absolute paths. The Native checkout supplies source
owners; the controller transfers no installed executable contents. The remote
bootstrap's closed `connector_hold` mode preserves the actual account environment
so installed provider paths remain available. The older fixture mode keeps its
separate minimal environment. Neither mode accepts a caller-supplied environment
map.

SSH aliases, run identities and device identities must be distinct within the
selected roster. The controller freezes that roster before starting anything;
it starts no unselected peer. A one-device hold can therefore leave another
device's existing connector untouched.

```sh
python3 scripts/e2e_connector_hold.py --config /absolute/private/hold.json
```

Keep this foreground command's stdin open during acceptance. Send `stop` followed
by a newline, or close stdin, to request shutdown. Closed stdin at startup stops
the hold after all selected targets have been started: the controller first reads stdin
after startup. The absolute remote deadline includes buffered operations; idle
and operation limits also apply. SSH peer heartbeats refresh the input idle
bound within that deadline; they do not establish WSS connectivity. Local progress
publication has a finite output deadline.

Only new staging and receipt paths and the exact connector child belong to this
run. Configurations, credentials, Native roots/projects and tasks remain external
and are never adopted or deleted. Receipts and source stages remain retained.
The controller attempts every selected peer's shutdown and join even after a
sibling failure. Acceptance requires one final result per selected target,
remote final receipts, the connector's actual
Native-owned Wait and each local SSH child's independent Wait. A missing proof
retains known locators and reports uncertainty; it never searches for, adopts or
signals a guessed process. `task_stop_proven` remains false: connector termination
does not establish provider-task termination. Check Delegate's canonical closure
through the original task identity separately.
