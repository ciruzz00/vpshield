VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test dist clean install

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o vpshield ./cmd/vpshield

test:
	go vet ./...
	go test ./...

dist:
	mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vpshield-linux-$$arch ./cmd/vpshield; \
	done
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vpshield-linux-armv7 ./cmd/vpshield
	cd dist && sha256sum vpshield-* > SHA256SUMS

install: build
	install -m 0755 vpshield /usr/local/bin/vpshield

clean:
	rm -rf dist vpshield
