.PHONY: test race vet build fmt-check ci
test:
	cd go && go test ./...
race:
	cd go && go test -race ./...
vet:
	cd go && go vet ./...
build:
	cd go && go build -trimpath -o zscaler-mdr-mcp ./cmd/server
fmt-check:
	test -z "$$(gofmt -l go)"
ci: fmt-check vet test race build
