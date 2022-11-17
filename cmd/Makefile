.PHONY: all lint clean

binary = nitriding
godeps = *.go ../*.go ../go.mod ../go.sum

all: lint $(binary)

lint:
	golangci-lint run

$(binary): $(godeps)
	go build -o $(binary)

clean:
	rm -f $(binary)
