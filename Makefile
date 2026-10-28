# Standard targets shared by all SoroSentinel repos (docs/project_structure.md §2.2).
# Thin wrapper over native Go tooling; `go` commands stay usable directly.

GO ?= go

.PHONY: deps fmt lint test test-integration test-contract gen migrate docs-check verify

deps:
	$(GO) mod download
	$(GO) mod verify

fmt:
	gofmt -w .

lint:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	$(GO) vet ./...
	$(GO) run ./cmd/wordlint -dir wording -docs docs/methodology

# Store integration tests skip unless INTEL_TEST_DATABASE_URL is set (CI runs unit tests only).
test:
	$(GO) test ./...

# Needs a disposable Postgres 16; see internal/store/store_test.go for a docker command.
test-integration:
	@if [ -z "$$INTEL_TEST_DATABASE_URL" ]; then echo "test-integration: set INTEL_TEST_DATABASE_URL"; exit 2; fi
	$(GO) test -count=1 ./internal/store/...

# Applies migrations/ (forward-only) to INTEL_DATABASE_URL.
migrate:
	$(GO) run ./internal/store/cmd/migrate

# Provider-side contract checks: shared vectors that Scan and Guard also run.
test-contract:
	$(GO) test -count=1 -run 'Vectors|Schemas' ./schemas/... ./internal/entity/... ./internal/wording/...

# TODO: choose a schema code generator (needs dependency approval). Until then
# schemas are validated as well-formed by `make test` and nothing is generated.
gen:
	@echo "gen: no code generator chosen yet; schemas/generated/ stays empty"

# Generated AGENTS.md (and sibling copies, when checked out) match docs/.
docs-check:
	scripts/sync-docs.sh --check

verify: lint test test-contract docs-check
