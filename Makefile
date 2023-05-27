binary = nitriding
godeps = *.go go.mod go.sum

all: lint test $(binary)

.PHONY: lint
lint: $(godeps)
	golangci-lint run

.PHONY: test
test: $(godeps)
	go test -cover ./...

$(binary): $(godeps)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -buildvcs=false -o $(binary)

.PHONY: clean
clean:
	rm -f $(binary)
