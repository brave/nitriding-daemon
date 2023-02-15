.PHONY: all lint clean

binary = nitriding
godeps = *.go ../*.go ../go.mod ../go.sum Makefile

all: lint $(binary)

lint:
	golangci-lint run

$(binary): $(godeps)
	CGO_ENABLED=0 go build -o $(binary)

clean:
	rm -f $(binary)
