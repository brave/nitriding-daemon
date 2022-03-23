.PHONY: test

godeps = *.go go.mod go.sum

test: $(godeps)
	@go test -cover ./...
