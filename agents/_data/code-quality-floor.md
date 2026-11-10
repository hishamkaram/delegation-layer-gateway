# Code quality floor

[Makefile](../../Makefile) owns executable gate recipes; [go.mod](../../go.mod)
and [.go-version](../../.go-version) own the compiler requirement. Read those
files rather than assuming the host compiler is compatible. Use
`GOTOOLCHAIN=local`; a missing required compiler is an actionable blocker,
never permission for an ambient toolchain download.

The module minimum is Go 1.27.0; the exact compiler pin is Go 1.27.3.
The approved tool pins are gofumpt v0.12.0,
golangci-lint v2.14.0 and govulncheck v1.8.0. Python 3.12+ runs the
stdlib-only harness validator. Contributor tools remain repository-local;
never mutate system configuration or substitute incompatible installed versions.
Python scripts use repository-local Ruff 0.15.20, installed from hash-pinned
wheels by `make tools-python`; `make lint-python` checks lint and formatting.

Preserve the adapted Delegate lint floor: explicit errcheck, govet, staticcheck,
unused, ineffassign, nilerr, errorlint, errname, forcetypeassert, contextcheck,
exhaustive, gocognit, gocyclo, bodyclose, sqlclosecheck, rowserrcheck, reassign,
gocheckcompilerdirectives, loggercheck, durationcheck, nolintlint and forbidigo
rules. No blanket exclusions or suppression to force green. Formatting is
standalone gofumpt. Root owns configured tooling and any unresolved toolchain gap.

`make check` requires formatting, vet, lint, unit/integration `-race`, build,
vulnerability checks, harness validation and docs checks. Focused editing checks
do not substitute for this gate. Run the exact configured targets; missing tools
or unavailable checks must fail with actionable guidance. Do not silently skip.

Tests need independent expected outcomes and success/failure boundaries. Bug
regressions must detect the intended defect. Real stores/consumers prove durable
behavior; fixtures do not prove installed provider, native host or cloud-client
compatibility. No empty-filter or all-skipped pass. Do not repeat unchanged suites
without a changed input or concrete risk. Root records integrated gate evidence.
