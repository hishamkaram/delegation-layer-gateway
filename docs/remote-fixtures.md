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
before deadline and credential revocation after task closure. A missed timing or
cleanup condition fails acceptance; budgets are not extended to obtain a pass.

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
