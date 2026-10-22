# AssessMatrix SDK — run `make` to see everything available.
.DEFAULT_GOAL := help
.PHONY: help sync generate check

BIN := $(shell go env GOPATH)/bin

help: ## Show this help
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-10s\033[0m %s\n", $$1, $$2}'

sync: ## Copy the schema from ../AssessMatrix (AM_REPO=path to override), then regenerate
	@./scripts/sync-proto.sh
	@$(MAKE) generate

generate: ## Lint the schema and regenerate the Go stubs under gen/
	@cd proto && PATH="$$PATH:$(BIN)" sh -c 'buf lint && buf generate'

check: ## Vet and test
	@go vet ./... && go test -race -count=1 ./...
