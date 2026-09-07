.PHONY: build generate test race vet integration clean

build:
	go build -trimpath -o bin/vigil ./cmd/vigil

generate:
	go generate ./internal/probe

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

integration:
	VIGIL_INTEGRATION=1 go test -count=1 -v ./tests/integration

clean:
	go clean ./...
