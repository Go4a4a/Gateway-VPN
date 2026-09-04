package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"unicode/utf8"
)

func FuzzImport(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("vless://11111111-1111-1111-1111-111111111111@proxy.example.com:443?security=tls#LTE%20Bypass"),
		[]byte("proxies:\n  - {name: bypass, type: trojan, server: proxy.example.com, port: 443, password: fixture-password-not-production}\n"),
		[]byte("c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2Wm1sNGRIVnlaUzF3WVhOemQyOXlaRUJ3Y205NGVTNWxlR0Z0Y0d4bExtTnZiVG8wTkRNPVx1MDAwYw=="),
		[]byte("proxies:\n  - {name: bad, type: vless, server: 127.0.0.1, port: 443, uuid: id}\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		result, err := Import(payload)
		if err != nil {
			return
		}
		if result.Format != "clash-yaml" && result.Format != "uri-list" && result.Format != "base64-clash-yaml" && result.Format != "base64-uri-list" {
			t.Fatalf("successful import returned unsupported format %q", result.Format)
		}
		if len(result.Nodes) == 0 || len(result.Nodes) > MaxNodes {
			t.Fatalf("successful import returned %d nodes", len(result.Nodes))
		}
		seen := make(map[string]struct{}, len(result.Nodes))
		for _, node := range result.Nodes {
			if node.ExternalName == "" || !utf8.ValidString(node.ExternalName) || len([]byte(node.ExternalName)) > MaxNodeNameBytes {
				t.Fatalf("successful import returned an unsafe external name")
			}
			if node.MatchName == "" || node.NormalizedName == "" || !utf8.ValidString(node.MatchName) || !utf8.ValidString(node.NormalizedName) {
				t.Fatalf("successful import returned an unsafe normalized name")
			}
			decoded, decodeErr := hex.DecodeString(node.Fingerprint)
			if decodeErr != nil || len(decoded) != sha256.Size {
				t.Fatalf("successful import returned invalid fingerprint %q", node.Fingerprint)
			}
			if _, duplicate := seen[node.Fingerprint]; duplicate {
				t.Fatalf("successful import returned duplicate fingerprint %q", node.Fingerprint)
			}
			seen[node.Fingerprint] = struct{}{}
			for field := range node.Config {
				if controllerOwnedFields[field] || !allowedProxyFields[field] {
					t.Fatalf("successful import retained forbidden proxy field %q", field)
				}
			}
		}
	})
}
