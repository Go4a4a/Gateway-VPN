// Package tlsbootstrap creates and validates the first-run management TLS
// certificate.
package tlsbootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Result struct {
	Created     bool
	Fingerprint string
}

func Ensure(certPath, keyPath string, hosts []string) (Result, error) {
	certExists, err := regularFileExists(certPath, false)
	if err != nil {
		return Result{}, err
	}
	keyExists, err := regularFileExists(keyPath, true)
	if err != nil {
		return Result{}, err
	}
	if certExists != keyExists {
		return Result{}, errors.New("TLS certificate and key must either both exist or both be absent")
	}
	if certExists {
		fingerprint, err := validatePair(certPath, keyPath)
		return Result{Fingerprint: fingerprint}, err
	}
	if len(hosts) == 0 {
		return Result{}, errors.New("at least one TLS certificate host is required")
	}
	certPEM, keyPEM, err := generate(hosts, time.Now().UTC())
	if err != nil {
		return Result{}, err
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return Result{}, fmt.Errorf("write TLS certificate: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath)
		return Result{}, fmt.Errorf("write TLS private key: %w", err)
	}
	fingerprint, err := validatePair(certPath, keyPath)
	return Result{Created: true, Fingerprint: fingerprint}, err
}

func generate(hosts []string, now time.Time) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS private key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS serial: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Gateway VPN"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := make(map[string]struct{})
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			return nil, nil, errors.New("TLS certificate host cannot be empty")
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		if address := net.ParseIP(host); address != nil {
			template.IPAddresses = append(template.IPAddresses, address)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal TLS private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func validatePair(certPath, keyPath string) (string, error) {
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	certBlock, _ := pem.Decode(certificatePEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return "", errors.New("invalid TLS PEM files")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse TLS certificate: %w", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse TLS private key: %w", err)
	}
	ecdsaKey, keyOK := privateKey.(*ecdsa.PrivateKey)
	publicKey, publicOK := certificate.PublicKey.(*ecdsa.PublicKey)
	if !keyOK || !publicOK || !publicKey.Equal(&ecdsaKey.PublicKey) {
		return "", errors.New("TLS certificate and private key do not match")
	}
	digest := sha256.Sum256(certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(digest[:])), nil
}

func regularFileExists(filename string, private bool) (bool, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, errors.New("TLS material must be regular non-symlink files")
	}
	if private && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return false, errors.New("TLS private key permissions must be 0600 or stricter")
	}
	return true, nil
}

func writeFileAtomic(filename string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".tls-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, filename)
}
