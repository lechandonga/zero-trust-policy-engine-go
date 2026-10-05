GO ?= go

.PHONY: test test-race vet build tidy

test:
	CGO_ENABLED=1 $(GO) test -race -v ./...

test-fast:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build ./...

tidy:
	$(GO) mod tidy
