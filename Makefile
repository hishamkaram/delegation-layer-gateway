SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

ifneq ($(filter-out local,$(GOTOOLCHAIN)),)
  $(error GOTOOLCHAIN must be unset or local; select the pinned installed compiler on PATH)
endif
export GOTOOLCHAIN := local

.PHONY: tools tools-python lint-python compiler packages tool-versions verify-harness check-docs test-tooling fmt-check vet lint test-race test-e2e-helper build vuln check e2e-client e2e-local e2e-provider e2e-external

tools:
	python3 scripts/tools.py install
	$(MAKE) tools-python

tools-python:
	python3 -m venv bin/python-lint
	bin/python-lint/bin/python -m pip install --require-hashes -r tools/python-requirements.txt

lint-python:
	@test "$$(bin/python-lint/bin/ruff --version)" = 'ruff 0.15.20' || { echo 'Run make tools-python for pinned Ruff' >&2; exit 1; }
	bin/python-lint/bin/ruff check scripts
	bin/python-lint/bin/ruff format --check scripts

compiler:
	python3 scripts/tools.py compiler

packages:
	python3 scripts/tools.py packages

tool-versions:
	python3 scripts/tools.py verify

verify-harness:
	python3 scripts/verify_harness.py

check-docs:
	python3 scripts/verify_harness.py --docs
	python3 scripts/verify_diagrams.py

test-tooling:
	python3 -m unittest discover -s scripts -p 'test_*.py'

fmt-check: tool-versions
	python3 scripts/tools.py format-check

vet: packages
	go vet ./...
	go vet -tags=e2e ./internal/e2e

lint: tool-versions
	bin/golangci-lint config verify
	bin/golangci-lint run ./...
	bin/golangci-lint run --build-tags=e2e ./internal/e2e/...

test-race: packages
	go test -race -count=1 -timeout=30m ./...

test-e2e-helper: packages
	go test -race -tags=e2e -count=1 -timeout=5m ./internal/e2e

build: packages
	go build ./...

vuln: tool-versions packages
	bin/govulncheck -tags=e2e ./...

check:
	$(MAKE) verify-harness check-docs test-tooling lint-python
	$(MAKE) fmt-check vet lint test-race test-e2e-helper build vuln

e2e-local: compiler
	go build -o bin/gateway-e2e ./cmd/gateway
	go build -tags=e2e -o bin/gateway-e2e-fixture ./internal/e2e
	python3 scripts/e2e_local.py --gateway "$(CURDIR)/bin/gateway-e2e" --fixture-tool "$(CURDIR)/bin/gateway-e2e-fixture" $(E2E_ARGS)

e2e-client: compiler
	go build -tags=e2e -o bin/gateway-e2e-fixture ./internal/e2e

e2e-provider: e2e-client
	python3 scripts/e2e_live.py provider $(E2E_ARGS)

e2e-external: e2e-client
	python3 scripts/e2e_live.py preflight $(E2E_ARGS)
