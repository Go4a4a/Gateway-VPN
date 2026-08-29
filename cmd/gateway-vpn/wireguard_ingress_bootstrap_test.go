package main

import "testing"

func TestWireGuardIngressBootstrapDryRunIsTypedAndNonMutating(t *testing.T) {
	if code := runWireGuardIngressBootstrap([]string{
		"--endpoint-host", "vpn.example.org", "--subnet", "10.90.0.0/24",
		"--listen-port", "51820", "--dns", "1.1.1.1,9.9.9.9",
	}); code != 0 {
		t.Fatalf("valid dry-run code = %d", code)
	}
	if code := runWireGuardIngressBootstrap([]string{
		"--endpoint-host", "vpn.example.org", "--subnet", "10.90.0.0/24",
		"--listen-port", "51821", "--dns", "10.90.0.1",
	}); code != 2 {
		t.Fatalf("invalid dry-run code = %d", code)
	}
}
