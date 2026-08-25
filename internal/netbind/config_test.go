package netbind

import "testing"

func TestConfigValidation(t *testing.T) {
	if err := (Config{InterfaceName: "enx0001", Fwmark: 0x1101}).Validate(); err != nil {
		t.Fatalf("valid config error = %v", err)
	}
	for _, input := range []Config{{Fwmark: 1}, {InterfaceName: "enx0001"}, {InterfaceName: "bad interface", Fwmark: 1}} {
		if err := input.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", input)
		}
	}
}
