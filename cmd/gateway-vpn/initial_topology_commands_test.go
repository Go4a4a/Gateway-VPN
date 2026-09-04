package main

import (
	"encoding/base64"
	"testing"

	"gateway-vpn/internal/installtopology"
)

func TestInitialTopologyCheckIsStrictAndReadOnly(t *testing.T) {
	token, err := installtopology.EncodeToken(installtopology.Plan{
		Profile: installtopology.ProfileEthernetHiLink, LANMembers: []string{"enp2s0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := runInitialTopologyCheck([]string{"--token", token}); code != 0 {
		t.Fatalf("runInitialTopologyCheck(valid) = %d", code)
	}
	if code := runInitialTopologyCheck([]string{"--token", token, "--lan-interface", "enp2s0"}); code != 0 {
		t.Fatalf("runInitialTopologyCheck(bound valid) = %d", code)
	}
	if code := runInitialTopologyCheck([]string{"--token", token, "--lan-interface", "enp3s0"}); code != 1 {
		t.Fatalf("runInitialTopologyCheck(bound mismatch) = %d", code)
	}
	bridgeToken, err := installtopology.EncodeToken(installtopology.Plan{
		Profile: installtopology.ProfileEthernetHiLink, LANMembers: []string{"enp3s0", "enp2s0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := runInitialTopologyCheck([]string{"--token", bridgeToken, "--lan-interface", "gateway-vpn-lan", "--lan-members", "enp2s0,enp3s0"}); code != 0 {
		t.Fatalf("runInitialTopologyCheck(bridge valid) = %d", code)
	}
	foreign := base64.RawURLEncoding.EncodeToString([]byte(`{"profile":"ETHERNET_HILINK","lan_members":["enp2s0"],"private_key":"forbidden"}`))
	if code := runInitialTopologyCheck([]string{"--token", foreign}); code != 1 {
		t.Fatalf("runInitialTopologyCheck(foreign) = %d", code)
	}
	if code := runInitialTopologyCheck(nil); code != 2 {
		t.Fatalf("runInitialTopologyCheck(empty) = %d", code)
	}
}
