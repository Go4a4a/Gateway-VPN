package main

import "testing"

func TestInteractiveModeRejectsBuildTimeHardwareAndApplyPolicy(t *testing.T) {
	for _, arguments := range [][]string{
		{"install-gateway", "--interactive", "--lan-interface", "enp2s0"},
		{"install-gateway", "--interactive", "--lan-address", "192.168.200.1/24"},
		{"install-gateway", "--interactive", "--enable-dhcp"},
		{"install-gateway", "--interactive", "--disable-ssh"},
		{"install-gateway", "--interactive", "--install-dependencies"},
		{"install-gateway", "--interactive", "--apply"},
		{"install-gateway", "--interactive", "--json"},
	} {
		if code := run(arguments); code != 2 {
			t.Errorf("run(%q) code = %d, want 2", arguments, code)
		}
	}
}

func TestManagementPeerIsInteractiveOnly(t *testing.T) {
	if code := run([]string{"install-gateway", "--management-peer", "203.0.113.10"}); code != 2 {
		t.Fatalf("non-interactive management peer code = %d, want 2", code)
	}
}
