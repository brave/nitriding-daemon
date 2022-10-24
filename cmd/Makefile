.PHONY: all lint clean

binary = nitriding
godeps = *.go

all: lint $(binary)

lint:
	golangci-lint run

$(binary): $(godeps)
	go build -o $(binary)

clean:
	rm $(binary)
