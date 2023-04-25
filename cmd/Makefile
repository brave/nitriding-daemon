.PHONY: all lint test clean

binary = nitriding
godeps = *.go ../*.go ../go.mod ../go.sum Makefile

all: lint $(binary)

lint:
	golangci-lint run

test: $(godeps)
	@go test -cover ./...

$(binary): $(godeps)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -buildvcs=false -o $(binary)

clean:
	rm -f $(binary)
