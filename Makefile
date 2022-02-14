# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

OS = $(shell uname | tr A-Z a-z)
export PATH := $(abspath bin/):${PATH}

# Dependency versions
GOLANGCI_VERSION = 1.44.0
TARP_VERSION = 0.1.3
REVIVE_VERSION = 1.1.3

# Add the ability to override some variables
# Use with care
-include override.mk

.PHONY: clear
clear: ## Clear the working area and the project
	rm -rf bin/

.PHONY: check
check: test lint ## Run tests and linters

.PHONY: test
test: export CGO_ENABLED=1
test: ## Run tests
	go test

.PHONY: cover
cover: bin/tarp ## Run tests and make coverage report
	go test -coverprofile mimic.cover
	bin/tarp mimic.cover -o mimic.cover.html
	xdg-open mimic.cover.html &
	
bin/tarp: bin/tarp-${TARP_VERSION}
	@ln -sf tarp-${TARP_VERSION} bin/tarp
bin/tarp-${TARP_VERSION}: export GOBIN=$(shell pwd)/bin
bin/tarp-${TARP_VERSION}:
	@mkdir -p bin
	go install github.com/dylandreimerink/tarp/cmd/tarp@v${TARP_VERSION}
	@mv bin/tarp $@

bin/revive: bin/revive-${REVIVE_VERSION}
	@ln -sf revive-${REVIVE_VERSION} bin/revive
bin/revive-${REVIVE_VERSION}: export GOBIN=$(shell pwd)/bin
bin/revive-${REVIVE_VERSION}:
	@mkdir -p bin
	go install github.com/mgechev/revive@v${REVIVE_VERSION}
	@mv bin/revive $@

bin/golangci-lint: bin/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} bin/golangci-lint
bin/golangci-lint-${GOLANGCI_VERSION}:
	@mkdir -p bin
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b ./bin/ v${GOLANGCI_VERSION}
	@mv bin/golangci-lint $@

.PHONY: lint
lint: bin/golangci-lint bin/revive ## Run linter
	bin/golangci-lint run
	bin/revive -set_exit_status=1

.PHONY: fix
fix: bin/golangci-lint ## Fix lint violations
	bin/golangci-lint run --fix

.PHONY: list
list: ## List all make targets
	@${MAKE} -pRrn : -f $(MAKEFILE_LIST) 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort

.PHONY: help
.DEFAULT_GOAL := help
help:
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Variable outputting/exporting rules
var-%: ; @echo $($*)
varexport-%: ; @echo $*=$($*)