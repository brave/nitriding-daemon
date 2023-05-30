binary = nitriding
godeps = *.go go.mod go.sum
cover_out = cover.out
cover_html = cover.html

all: lint test $(binary)

.PHONY: lint
lint: $(godeps)
	golangci-lint run

.PHONY: test
test: $(godeps)
	go test -cover ./...

.PHONY: coverage
coverage: $(cover_html)
	${BROWSER} $(cover_html)

$(cover_html): $(cover_out)
	go test -coverprofile=$(cover_out) .
	go tool cover -html=$(cover_out) -o $(cover_html)

$(binary): $(godeps)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -buildvcs=false -o $(binary)

.PHONY: clean
clean:
	rm -f $(binary)
	rm -f $(cover_out) $(cover_html)
