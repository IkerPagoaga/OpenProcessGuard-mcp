BINARY  := processguard-mcp.exe
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(DATE)

.PHONY: build test vet fmt lint vuln check

## build: cross-compile the Windows binary with version metadata
build:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## test: run the suite with the race detector and coverage
test:
	go test -race -cover ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

## lint: static analysis (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
lint:
	staticcheck ./...

## vuln: dependency CVE scan (install: go install golang.org/x/vuln/cmd/govulncheck@latest)
vuln:
	govulncheck ./...

## check: the full local pre-commit gate
check: fmt vet test vuln
