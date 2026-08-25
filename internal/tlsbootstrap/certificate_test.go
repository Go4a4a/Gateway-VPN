package tlsbootstrap

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCreatesStableMatchingCertificateWithSANs(t *testing.T) {
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "tls", "cert.pem"), filepath.Join(root, "tls", "key.pem")
	first, err := Ensure(certPath, keyPath, []string{"192.168.200.1", "10.80.0.2"})
	if err != nil || !first.Created || first.Fingerprint == "" {
		t.Fatalf("Ensure(first) = %+v, %v", first, err)
	}
	second, err := Ensure(certPath, keyPath, []string{"192.168.200.1"})
	if err != nil || second.Created || second.Fingerprint != first.Fingerprint {
		t.Fatalf("Ensure(second) = %+v, %v", second, err)
	}
	content, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(content)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(certificate.IPAddresses) != 2 {
		t.Fatalf("certificate SANs = %v, %v", certificate.IPAddresses, err)
	}
}

func TestEnsureRejectsPartialPair(t *testing.T) {
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(certPath, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(certPath, keyPath, []string{"192.168.200.1"}); err == nil {
		t.Fatal("Ensure(partial pair) error = nil")
	}
}
