BIN := gitsafe
PKG := ./...

.PHONY: build test lint clean install snapshot release-check

build:
	go build -o $(BIN) ./cmd/gitsafe

test:
	go test $(PKG)

e2e:
	go test ./cmd/gitsafe -run TestEndToEnd -v

lint:
	go vet $(PKG)

clean:
	rm -f $(BIN)

install: build
	install -m 0755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)

# Validate the GoReleaser config.
release-check:
	goreleaser check

# Build a local snapshot release into ./dist (no publish).
snapshot:
	goreleaser release --snapshot --clean
