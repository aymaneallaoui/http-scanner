.PHONY: all build test test-unit test-integration lint clean

BINARY_NAME=http-scanner
GOFLAGS=-ldflags="-s -w"

all: test build

build:
	go build ${GOFLAGS} -o ${BINARY_NAME} ./main.go

test: test-unit test-integration

test-unit:
	go test -v ./tests/unit/...

test-integration:
	go test -v ./tests/integration/...

lint:
	golangci-lint run ./...

clean:
	rm -f ${BINARY_NAME}
	go clean -cache


ci-test: test-unit test-integration


dev:
	air -c .air.toml

cover:
	go test -coverprofile=coverage ./...
	go tool cover -html=coverage