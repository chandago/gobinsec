-include ~/.make/color.mk
-include ~/.make/help.mk

BUILD_DIR = build
VERSION   = "UNKNOWN"
GOOSARCH  = $(shell go tool dist list | grep -v android)

.DEFAULT_GOAL :=
default: clean fmt lint test integ gobinsec

.PHONY: clean
clean: # Clean generated files
	$(title)
	@rm -rf $(BUILD_DIR)
	@go clean -testcache
	@go clean -cache
	@echo "$(GRE)OK$(END) cache cleaned"

.PHONY: fmt
fmt: # Format Go code
	$(title)
	@go fmt ./...
	@echo "$(GRE)OK$(END) code formatted"

.PHONY: lint
lint: # Check Go code
	$(title)
	@golangci-lint run ./...
	@echo "$(GRE)OK$(END) code linted"

.PHONY: gobinsec
gobinsec: build # Check binary for vulnerabilities
	$(title)
	@gobinsec -config .gobinsec.yml -wait $(shell find $(BUILD_DIR)/* -perm -u+x)
	@echo "$(GRE)OK$(END) code checked for vulnerabilities"

.PHONY: test
test: # Run unit tests
	$(title)
	@go test -cover ./...
	@echo "$(GRE)OK$(END) tests passed"

.PHONY: build
build: # Build binary
	$(title)
	@mkdir -p $(BUILD_DIR)
	@go build -ldflags "-X main.Version=$(VERSION) -s -f" -o $(BUILD_DIR)/ ./...
	@echo "$(GRE)OK$(END) binary built"

.PHONY: install
install: # Build and install tool
	$(title)
	@go install .
	@echo "$(GRE)OK$(END) binary installed"

.PHONY: integ
integ: build # Run integration test
	$(title)
	-@$(BUILD_DIR)/gobinsec test/binary > $(BUILD_DIR)/report.yml
	@test $? || (echo "ERROR should have exited with code 1" && exit 1)
	@cmp test/report.yml $(BUILD_DIR)/report.yml
	@cat test/config.yml | envsubst > $(BUILD_DIR)/config.yml
	@$(BUILD_DIR)/gobinsec -verbose -config $(BUILD_DIR)/config.yml test/binary > $(BUILD_DIR)/report-config.yml
	@cmp test/report-config.yml $(BUILD_DIR)/report-config.yml
	@echo "$(GRE)OK$(END) integration tests passed"

.PHONY: binaries
binaries: # Generate binaries
	$(title)
	@mkdir -p $(BUILD_DIR)/bin
	@gox -ldflags "-X main.Version=$(VERSION) -s -f" -osarch '$(GOOSARCH)' -output=$(BUILD_DIR)/bin/{{.Dir}}-{{.OS}}-{{.Arch}} $(GOPACKAGE)
	@cp install $(BUILD_DIR)/bin/
	@echo "$(GRE)OK$(END) binaries generated"

.PHONY: archive
archive: clean binaries # Generate archive
	$(title)
	@cp README.md LICENSE.txt $(BUILD_DIR)/
	@cd $(BUILD_DIR) && tar -czf gobinsec-$(VERSION).tar.gz *
	@echo "$(GRE)OK$(END) archive generated"

.PHONY: release
release: clean lint test integ gobinsec archive # Perform release (must pass VERSION=X.Y.Z on command line)
	$(title)
	@if [ "$(VERSION)" = "UNKNOWN" ]; then \
		echo "ERROR you must pass VERSION=X.Y.Z on command line"; \
		exit 1; \
	fi
	@git diff-index --quiet HEAD -- || (echo "ERROR There are uncommitted changes" && exit 1)
	@test `git rev-parse --abbrev-ref HEAD` = 'main' || (echo "ERROR You are not on branch main" && exit 1)
	@git tag -a $(VERSION) -m "Release $(VERSION)"
	@git push origin --tags
	@echo "$(GRE)OK$(END) release $(VERSION) created and pushed"

.PHONY: memcached
memcached: # Start memcached
	$(title)
	@docker-compose up -d memcached
	@echo "$(GRE)OK$(END) memcached started"
