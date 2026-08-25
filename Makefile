.PHONY: test build check fmt

test:
	go test ./...

build:
	go build -trimpath -o bin/gateway-vpn ./cmd/gateway-vpn
	go build -trimpath -o bin/gateway-vpnctl ./cmd/gateway-vpnctl
	go build -trimpath -o bin/gateway-vpn-deploy ./cmd/gateway-vpn-deploy

check: fmt
	go vet ./...
	go test ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)
