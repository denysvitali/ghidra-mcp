# bridge-go/Makefile

GO              ?= go
BINARY_NAME     := ghidra-mcp-bridge
DIST_DIR        := dist
LDFLAGS         := -s -w

.PHONY: build test test-unit cross-compile vet fmt lint tidy clean install run

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/$(BINARY_NAME) ./cmd/ghidra-mcp-bridge

cross-compile:
	@mkdir -p $(DIST_DIR)
	@for goos in linux darwin windows; do \
	  for goarch in amd64 arm64; do \
	    [ "$$goos$$goarch" = "windowsarm64" ] && continue || true; \
	    ext=$$( [ "$$goos" = "windows" ] && echo .exe || echo ); \
	    out=$(DIST_DIR)/$(BINARY_NAME)-$$goos-$$goarch$$ext; \
	    echo "==> $$out"; \
	    CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch \
	      $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
	        -o $$out ./cmd/ghidra-mcp-bridge; \
	  done; \
	done

test:
	$(GO) test ./...

test-unit:
	$(GO) test ./internal/...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(DIST_DIR)

install: build
	@mkdir -p $(HOME)/.local/bin
	cp $(DIST_DIR)/$(BINARY_NAME) $(HOME)/.local/bin/

run: build
	./$(DIST_DIR)/$(BINARY_NAME) --transport stdio