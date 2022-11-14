.PHONY: all test lint clean

binary = cmd/nitriding
godeps = *.go go.mod go.sum
cmddeps = cmd/*.go

all: test lint $(binary)

lint:
	golangci-lint run

test: $(godeps)
	@go test -cover ./...

$(binary): $(godeps) $(cmddeps)
	make -C cmd/

clean:
	make -C cmd/ clean
