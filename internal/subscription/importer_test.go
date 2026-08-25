package subscription

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestImportClashYAMLSanitizesAndFingerprintsNodes(t *testing.T) {
	payload := []byte(`proxies:
  - name: "  ОБХОД LTE  "
    type: vless
    server: bypass.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
  - name: Normal
    type: trojan
    server: normal.example.com
    port: 443
    password: secret
`)
	result, err := Import(payload)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if result.Format != "clash-yaml" || len(result.Nodes) != 2 {
		t.Fatalf("Import() result = %+v", result)
	}
	first := result.Nodes[0]
	if first.ExternalName != "ОБХОД LTE" || first.MatchName != "обход lte" || len(first.Fingerprint) != 64 {
		t.Fatalf("first node = %+v", first)
	}
	if _, exists := first.Config["interface-name"]; exists {
		t.Fatal("sanitized config contains controller-owned interface-name")
	}

	renamed := []byte(strings.Replace(string(payload), "ОБХОД LTE", "Renamed node", 1))
	renamedResult, err := Import(renamed)
	if err != nil {
		t.Fatalf("Import(renamed) error = %v", err)
	}
	if renamedResult.Nodes[0].Fingerprint != first.Fingerprint {
		t.Fatalf("rename changed stable fingerprint: %s != %s", renamedResult.Nodes[0].Fingerprint, first.Fingerprint)
	}
}

func TestImportURIAndWholeBase64Lists(t *testing.T) {
	uriList := "vless://11111111-1111-1111-1111-111111111111@bypass.example.com:443?security=tls&sni=cdn.example.com#LTE%20Bypass\n" +
		"trojan://password@normal.example.com:443#Normal\n"
	result, err := Import([]byte(uriList))
	if err != nil {
		t.Fatalf("Import(uri list) error = %v", err)
	}
	if result.Format != "uri-list" || len(result.Nodes) != 2 || result.Nodes[0].ProxyType != "vless" {
		t.Fatalf("URI result = %+v", result)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(uriList))
	base64Result, err := Import([]byte(encoded))
	if err != nil {
		t.Fatalf("Import(base64 list) error = %v", err)
	}
	if base64Result.Format != "base64-uri-list" || len(base64Result.Nodes) != 2 {
		t.Fatalf("base64 result = %+v", base64Result)
	}
}

func TestImportRejectsControllerFieldsPrivateEndpointsAndDuplicates(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"controller field", "proxies:\n  - {name: bad, type: vless, server: proxy.example.com, port: 443, uuid: id, interface-name: eth0}\n"},
		{"private endpoint", "proxies:\n  - {name: bad, type: vless, server: 192.168.1.2, port: 443, uuid: id}\n"},
		{"unsupported field", "proxies:\n  - {name: bad, type: vless, server: proxy.example.com, port: 443, uuid: id, malicious-command: x}\n"},
		{"duplicate fingerprint", "proxies:\n  - {name: one, type: vless, server: proxy.example.com, port: 443, uuid: same}\n  - {name: two, type: vless, server: proxy.example.com, port: 443, uuid: same}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Import([]byte(test.payload)); err == nil {
				t.Fatal("Import() error = nil")
			}
		})
	}
}

func TestImportRejectsOversizedPayload(t *testing.T) {
	if _, err := Import([]byte(strings.Repeat("x", MaxPayloadBytes+1))); err == nil {
		t.Fatal("Import(oversized) error = nil")
	}
}
