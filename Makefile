.PHONY: run build test clean

run:
	go run cmd/main.go

build:
	go build -o bin/auth cmd/main.go

test:
	go test -v ./...

clean:
	rm -rf bin/
