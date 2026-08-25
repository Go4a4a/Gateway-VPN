package hilink

import (
	"context"
	"strings"
	"testing"

	"gateway-vpn/internal/modem"
)

type fakeProbe struct{ devices []RawDevice }

func (probe fakeProbe) ListUSBNetworkDevices(context.Context) ([]RawDevice, error) {
	return probe.devices, nil
}

func TestDiscoveryUsesStrongestSaltedIdentityAndRejectsAmbiguousMatch(t *testing.T) {
	salt := []byte(strings.Repeat("s", 32))
	candidates, err := Discover(context.Background(), fakeProbe{devices: []RawDevice{
		{InterfaceName: "enxone", VendorID: "12D1", ProductID: "14dc", USBSerial: "SERIAL-1234", PermanentMAC: "00:11:22:33:44:55", USBTopology: "pci/usb1/1-1", Carrier: true},
		{InterfaceName: "ignored", VendorID: "1234", ProductID: "0001", PermanentMAC: "00:11:22:33:44:66"},
	}}, Options{IdentitySalt: salt})
	if err != nil || len(candidates) != 1 {
		t.Fatalf("Discover() = %+v, %v", candidates, err)
	}
	candidate := candidates[0]
	if candidate.IdentityKind != "usb_serial_hash" || len(candidate.IdentityHash) != 64 || candidate.MaskedSerial != "****1234" || strings.Contains(candidate.IdentityHash, "SERIAL") {
		t.Fatalf("candidate = %+v", candidate)
	}
	matched := MatchAdopted(candidates, []modem.Modem{{ID: "modem-a", IdentityKind: candidate.IdentityKind, IdentityHash: candidate.IdentityHash}})
	if matched[0].State != DiscoveryMatched || matched[0].ModemID != "modem-a" {
		t.Fatalf("matched = %+v", matched)
	}
	duplicate := append(candidates, candidate)
	duplicate[1].InterfaceName = "enxtwo"
	matched = MatchAdopted(duplicate, []modem.Modem{{ID: "modem-a", IdentityKind: candidate.IdentityKind, IdentityHash: candidate.IdentityHash}})
	if matched[0].State != DiscoveryAmbiguous || matched[1].State != DiscoveryAmbiguous {
		t.Fatalf("ambiguous matches = %+v", matched)
	}
}
