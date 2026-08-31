package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStagerAcceptsVerifiedArchiveAndDiscardIsExact(t *testing.T) {
	releaseRoot, publicKey, _ := signedReleaseFixture(t, "1.2.0", 11, 12)
	stateDir := t.TempDir()
	keyPath := writePublicKeyFixture(t, stateDir, publicKey)
	stager, err := NewStager(stateDir, keyPath, fixturePolicy(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	stager.Now = func() time.Time { return time.Date(2026, 8, 24, 21, 0, 0, 0, time.UTC) }
	operation, err := stager.Stage(context.Background(), bytes.NewReader(releaseArchive(t, releaseRoot, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if operation.GatewayVersion != "1.2.0" || operation.FileCount != 7+len(requiredHostContractFiles) || operation.UncompressedBytes <= 0 || !updateIDPattern.MatchString(operation.UpdateID) {
		t.Fatalf("staged operation = %+v", operation)
	}
	status, exists, err := stager.Status()
	if err != nil || !exists || status != operation {
		t.Fatalf("Status() = %+v,%v,%v", status, exists, err)
	}
	if _, err := stager.Stage(context.Background(), bytes.NewReader(releaseArchive(t, releaseRoot, nil))); err != ErrUpdatePending {
		t.Fatalf("second Stage() error = %v", err)
	}
	if err := stager.Discard(context.Background(), "update-20260824T210000Z-000000000000000000000000"); err == nil {
		t.Fatal("different update id discarded the pending release")
	}
	if err := stager.Discard(context.Background(), operation.UpdateID); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := stager.Status(); err != nil || exists {
		t.Fatalf("status after discard = %v,%v", exists, err)
	}
}

func TestStagerPersistsAutomaticChannelOwnership(t *testing.T) {
	releaseRoot, publicKey, _ := signedReleaseFixture(t, "1.2.0", 1, 32)
	stateDir := t.TempDir()
	keyPath := writePublicKeyFixture(t, stateDir, publicKey)
	stager, err := NewStager(stateDir, keyPath, fixturePolicy(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	operation, err := stager.StageWithSource(context.Background(), bytes.NewReader(releaseArchive(t, releaseRoot, nil)), Source{
		Kind: SourceAutomaticGitHub, Channel: "stable", Reference: "Go4a4a/Gateway-VPN#v1.2.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	status, pending, err := stager.Status()
	if err != nil || !pending || status != operation || status.SourceKind != SourceAutomaticGitHub || status.SourceChannel != "stable" {
		t.Fatalf("automatic source status = %+v,%t,%v", status, pending, err)
	}
}

func TestStagerRejectsArchiveTraversalLinksDuplicatesAndTamper(t *testing.T) {
	releaseRoot, publicKey, privateKey := signedReleaseFixture(t, "1.2.0", 11, 12)
	cases := []struct {
		name    string
		entries []tarEntry
		mutate  func(string)
	}{
		{"traversal", []tarEntry{{Name: "../escape", Body: "escape", Mode: 0o644}}, nil},
		{"absolute", []tarEntry{{Name: "/escape", Body: "escape", Mode: 0o644}}, nil},
		{"symlink", []tarEntry{{Name: "link", Link: "release.json", Type: tar.TypeSymlink, Mode: 0o777}}, nil},
		{"duplicate", []tarEntry{{Name: "release.json", Body: "duplicate", Mode: 0o644}}, nil},
		{"tamper", nil, func(root string) {
			_ = os.WriteFile(filepath.Join(root, "bin", "gateway-vpn"), []byte("tamper"), 0o755)
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			root := releaseRoot
			if item.mutate != nil {
				root, _, _ = unsignedReleaseFixture(t, "1.2.0", 11, 12)
				if _, err := SignRelease(root, privateKey); err != nil {
					t.Fatal(err)
				}
				item.mutate(root)
			}
			stateDir := t.TempDir()
			keyPath := writePublicKeyFixture(t, stateDir, publicKey)
			stager, err := NewStager(stateDir, keyPath, fixturePolicy(publicKey))
			if err != nil {
				t.Fatal(err)
			}
			archive := releaseArchive(t, root, item.entries)
			if _, err := stager.Stage(context.Background(), bytes.NewReader(archive)); err == nil {
				t.Fatal("unsafe or unverified archive was staged")
			}
			if _, exists, err := stager.Status(); err != nil || exists {
				t.Fatalf("rejected archive left pending state: %v,%v", exists, err)
			}
		})
	}
}

func TestStagerRejectsTruncatedAndTrailingArchive(t *testing.T) {
	releaseRoot, publicKey, _ := signedReleaseFixture(t, "1.2.0", 11, 12)
	valid := releaseArchive(t, releaseRoot, nil)
	cases := map[string][]byte{
		"truncated-gzip-footer": valid[:len(valid)-4],
		"trailing-data":         append(append([]byte(nil), valid...), []byte("unsigned-trailer")...),
		"concatenated-member":   append(append([]byte(nil), valid...), valid...),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			keyPath := writePublicKeyFixture(t, stateDir, publicKey)
			stager, err := NewStager(stateDir, keyPath, fixturePolicy(publicKey))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stager.Stage(context.Background(), bytes.NewReader(archive)); err == nil {
				t.Fatal("ambiguous or truncated release archive was staged")
			}
		})
	}
}

type tarEntry struct {
	Name string
	Body string
	Mode int64
	Type byte
	Link string
}

func releaseArchive(t *testing.T, root string, extras []tarEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || path == root {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return tarWriter.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := int64(0o644)
		if strings.HasPrefix(name, "bin/") || name == "libexec/mihomo" || info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(content))}); err != nil {
			return err
		}
		_, err = tarWriter.Write(content)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range extras {
		typeflag := extra.Type
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: extra.Name, Typeflag: typeflag, Mode: extra.Mode, Linkname: extra.Link, Size: int64(len(extra.Body))}
		if typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size != 0 {
			if _, err := tarWriter.Write([]byte(extra.Body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writePublicKeyFixture(t *testing.T, directory string, key ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "trusted-update.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
