# Bug bounty toolkit build and verification targets.
#
# The default target is `check`, not `build`: for a security tool the useful
# thing to be able to type is the one that proves the tree is sound, so that is
# what a bare `make` does.

GO      ?= go
BINARY  ?= bugbounty
PKG     := ./...
CMD     := ./cmd/bugbounty
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILDDIR := dist

# -trimpath keeps module and build paths out of the binary, so a report's
# provenance does not leak the layout of the machine that produced it.
# -mod=readonly makes a missing go.sum entry an error rather than a silent
# edit to the dependency graph mid-build.
GOFLAGS  := -trimpath -mod=readonly
TESTFLAGS := -count=1

.DEFAULT_GOAL := check
.PHONY: help check build install test race vet fmt lint tidy clean verify-deps

help: ## List the available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

check: vet test ## Vet and test everything. The default.

build: ## Build the binary into dist/
	@mkdir -p $(BUILDDIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY) $(CMD)
	@echo "built $(BUILDDIR)/$(BINARY) ($(VERSION))"

install: ## Install the binary into GOBIN
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(CMD)

test: ## Run the test suite
	$(GO) test $(TESTFLAGS) $(PKG)

race: ## Run the test suite under the race detector
	@command -v gcc >/dev/null 2>&1 || { \
		echo "the race detector needs a C compiler; run this in CI or a container"; \
		exit 1; }
	$(GO) test $(TESTFLAGS) -race $(PKG)

vet: ## Run go vet
	$(GO) vet $(PKG)

fmt: ## Format the tree
	$(GO) fmt $(PKG)

lint: fmt vet ## Format then vet

tidy: ## Tidy the module graph
	$(GO) mod tidy

# Confirms the module graph is complete and the build is reproducible from a
# clean checkout, which is what CI needs to fail on.
verify-deps:
	$(GO) mod verify

clean: ## Remove build and scratch output
	rm -rf $(BUILDDIR) .tmp .gotmp
	$(GO) clean -testcache
