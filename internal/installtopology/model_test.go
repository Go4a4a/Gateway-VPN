package installtopology

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestPlanValidatesFourInitialProfiles(t *testing.T) {
	tests := []Plan{
		{Profile: ProfileEthernetHiLink, LANMembers: []string{"enp2s0", "enp3s0"}},
		{Profile: ProfileEthernetEthernet, LANMembers: []string{"enp2s0"}, EthernetUplinks: []EthernetUplink{{InterfaceName: "enp3s0", AddressMode: AddressDHCP}}},
		{Profile: ProfileOneArmWireGuard, SharedOneArmInterface: "enp2s0", EthernetUplinks: []EthernetUplink{{InterfaceName: "enp2s0", AddressMode: AddressDHCP}}},
		{Profile: ProfileMixed, LANMembers: []string{"enp2s0"}, EthernetUplinks: []EthernetUplink{{InterfaceName: "enp3s0", AddressMode: AddressStatic, IPv4CIDR: "192.168.10.2/24", Gateway: "192.168.10.1", DNS: []string{"1.1.1.1"}, MTU: 1500}}},
		{Profile: ProfileMixed, SharedOneArmInterface: "enp2s0", EthernetUplinks: []EthernetUplink{{InterfaceName: "enp2s0", AddressMode: AddressDHCP}}},
	}
	for _, plan := range tests {
		if err := plan.Validate(); err != nil {
			t.Fatalf("Validate(%s) = %v", plan.Profile, err)
		}
	}
}

func TestPlanRejectsRoleConflictsAndIncompleteProfiles(t *testing.T) {
	tests := []Plan{
		{Profile: ProfileEthernetHiLink},
		{Profile: ProfileEthernetHiLink, LANMembers: []string{"enp2s0"}, EthernetUplinks: []EthernetUplink{{InterfaceName: "enp3s0", AddressMode: AddressDHCP}}},
		{Profile: ProfileEthernetEthernet, LANMembers: []string{"enp2s0"}, EthernetUplinks: []EthernetUplink{{InterfaceName: "enp2s0", AddressMode: AddressDHCP}}},
		{Profile: ProfileOneArmWireGuard, LANMembers: []string{"enp2s0"}, SharedOneArmInterface: "enp2s0", EthernetUplinks: []EthernetUplink{{InterfaceName: "enp2s0", AddressMode: AddressDHCP}}},
		{Profile: ProfileOneArmWireGuard, SharedOneArmInterface: "enp2s0", EthernetUplinks: []EthernetUplink{{InterfaceName: "enp3s0", AddressMode: AddressDHCP}}},
		{Profile: ProfileMixed, LANMembers: []string{"enp2s0"}},
		{Profile: ProfileEthernetEthernet, LANMembers: []string{"enp2s0", "enp2s0"}, EthernetUplinks: []EthernetUplink{{InterfaceName: "enp3s0", AddressMode: AddressDHCP}}},
	}
	for _, plan := range tests {
		if err := plan.Validate(); err == nil {
			t.Fatalf("Validate(%+v) unexpectedly succeeded", plan)
		}
	}
}

func TestEthernetUplinkValidation(t *testing.T) {
	tests := []EthernetUplink{
		{InterfaceName: "enp2s0", AddressMode: AddressDHCP, IPv4CIDR: "192.168.1.2/24"},
		{InterfaceName: "enp2s0", AddressMode: AddressStatic, IPv4CIDR: "192.168.1.2/24", Gateway: "192.168.2.1"},
		{InterfaceName: "enp2s0", AddressMode: AddressStatic, IPv4CIDR: "192.168.1.2/24", Gateway: "192.168.1.1", DNS: []string{"0.0.0.0"}},
		{InterfaceName: "enp2s0", AddressMode: AddressStatic, IPv4CIDR: "192.168.1.2/24", Gateway: "192.168.1.1", MTU: 500},
	}
	for _, uplink := range tests {
		if err := validateEthernetUplink(uplink); err == nil {
			t.Fatalf("validateEthernetUplink(%+v) unexpectedly succeeded", uplink)
		}
	}
}

func TestCanonicalDoesNotMutateSource(t *testing.T) {
	plan := Plan{
		Profile:    ProfileEthernetEthernet,
		LANMembers: []string{"enp3s0", "enp2s0"},
		EthernetUplinks: []EthernetUplink{
			{InterfaceName: " enp5s0 ", AddressMode: "dhcp", DNS: []string{"1.1.1.1"}},
			{InterfaceName: "enp4s0", AddressMode: AddressDHCP},
		},
	}
	canonical := plan.Canonical()
	if canonical.LANMembers[0] != "enp2s0" || canonical.EthernetUplinks[0].InterfaceName != "enp4s0" || canonical.EthernetUplinks[1].AddressMode != AddressDHCP {
		t.Fatalf("Canonical() = %+v", canonical)
	}
	canonical.LANMembers[0] = "changed"
	canonical.EthernetUplinks[1].DNS[0] = "9.9.9.9"
	if plan.LANMembers[0] != "enp3s0" || plan.EthernetUplinks[0].DNS[0] != "1.1.1.1" {
		t.Fatal("Canonical mutated source slices")
	}
}

func TestTokenRoundTripIsCanonicalAndRejectsForeignFields(t *testing.T) {
	plan := Plan{
		Profile:    ProfileEthernetEthernet,
		LANMembers: []string{"enp3s0", "enp2s0"},
		EthernetUplinks: []EthernetUplink{
			{InterfaceName: "enp5s0", AddressMode: AddressDHCP},
			{InterfaceName: "enp4s0", AddressMode: AddressStatic, IPv4CIDR: "10.0.0.2/24", Gateway: "10.0.0.1"},
		},
	}
	token, err := EncodeToken(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeToken(token)
	if err != nil || decoded.LANMembers[0] != "enp2s0" || decoded.EthernetUplinks[0].InterfaceName != "enp4s0" {
		t.Fatalf("DecodeToken() = %+v, %v", decoded, err)
	}
	foreign := base64.RawURLEncoding.EncodeToString([]byte(`{"profile":"ETHERNET_HILINK","lan_members":["enp2s0"],"secret":"no"}`))
	if _, err := DecodeToken(foreign); err == nil {
		t.Fatal("DecodeToken accepted an unknown field")
	}
	if _, err := DecodeToken(token + "="); err == nil {
		t.Fatal("DecodeToken accepted a non-canonical base64 token")
	}
	if _, err := DecodeToken(strings.Repeat("a", base64.RawURLEncoding.EncodedLen(MaximumTokenBytes)+1)); err == nil {
		t.Fatal("DecodeToken accepted an oversized token")
	}
}

func TestCurrentLANPlanBindsSupportedInstallerArguments(t *testing.T) {
	direct, err := CurrentLANPlan("enp2s0", nil)
	if err != nil || len(direct.LANMembers) != 1 || direct.LANMembers[0] != "enp2s0" {
		t.Fatalf("direct CurrentLANPlan() = %+v, %v", direct, err)
	}
	bridge, err := CurrentLANPlan("gateway-vpn-lan", []string{"enp3s0", "enp2s0"})
	if err != nil || strings.Join(bridge.LANMembers, ",") != "enp2s0,enp3s0" {
		t.Fatalf("bridge CurrentLANPlan() = %+v, %v", bridge, err)
	}
	if err := ValidateCurrentLAN(bridge, "gateway-vpn-lan", []string{"enp3s0", "enp2s0"}); err != nil {
		t.Fatalf("ValidateCurrentLAN() = %v", err)
	}
	if err := ValidateCurrentLAN(direct, "enp3s0", nil); err == nil {
		t.Fatal("ValidateCurrentLAN accepted a different physical interface")
	}
	if _, err := CurrentLANPlan("gateway-vpn-lan", nil); err == nil {
		t.Fatal("CurrentLANPlan accepted a logical bridge without members")
	}
	if _, err := CurrentLANPlan("gateway-vpn-lan", []string{" enp2s0 ", "enp2s0"}); err == nil {
		t.Fatal("CurrentLANPlan accepted duplicate members after trimming")
	}
}
