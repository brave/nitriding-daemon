.PHONY: all test lint

godeps = *.go go.mod go.sum

all: test lint

lint:
	golangci-lint run

test: $(godeps)
	@go test -cover ./...
