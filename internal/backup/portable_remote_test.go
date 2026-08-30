package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type fakePortableExportSource struct {
	artifact   PortableArtifact
	content    []byte
	passphrase string
	err        error
}

func (source *fakePortableExportSource) ExportPortableBackup(_ context.Context, passphrase string) (PortableArtifact, io.ReadCloser, error) {
	source.passphrase = passphrase
	if source.err != nil {
		return PortableArtifact{}, nil, source.err
	}
	return source.artifact, io.NopCloser(bytes.NewReader(source.content)), nil
}

func TestRemotePortableManagerStoresOnlyVerifiedEncryptedBrokerStream(t *testing.T) {
	content := []byte("authenticated-encrypted-gvpn-stream")
	digest := sha256.Sum256(content)
	source := &fakePortableExportSource{
		content: content,
		artifact: PortableArtifact{
			Filename: "gateway-vpn-backup-20260830T150000Z-0123456789abcdef01234567.gvpn",
			Bytes:    int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
			SnapshotID: "20260830T150000.000000000Z-0123456789abcdef01234567",
		},
	}
	exportRoot := filepath.Join(t.TempDir(), "exports")
	manager, err := NewRemotePortableManager(source, exportRoot)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := "correct horse battery staple"
	artifact, err := manager.Build(context.Background(), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if source.passphrase != passphrase || artifact.Path != filepath.Join(exportRoot, artifact.Filename) {
		t.Fatalf("remote portable artifact/passphrase = %+v / %q", artifact, source.passphrase)
	}
	stored, err := os.ReadFile(artifact.Path)
	if err != nil || !bytes.Equal(stored, content) {
		t.Fatalf("stored encrypted artifact = %q, %v", stored, err)
	}
	reader, err := manager.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	opened, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(opened, content) {
		t.Fatalf("opened encrypted artifact = %q, %v, %v", opened, readErr, closeErr)
	}
	if err := manager.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifact.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remote encrypted artifact remains: %v", err)
	}
}

func TestRemotePortableManagerRejectsTamperedOrPathBearingBrokerMetadata(t *testing.T) {
	content := []byte("encrypted")
	digest := sha256.Sum256(content)
	valid := PortableArtifact{
		Filename: "gateway-vpn-backup-20260830T150000Z-0123456789abcdef01234567.gvpn",
		Bytes:    int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		SnapshotID: "20260830T150000.000000000Z-0123456789abcdef01234567",
	}
	cases := map[string]func(*fakePortableExportSource){
		"wrong digest": func(source *fakePortableExportSource) { source.artifact.SHA256 = string(bytes.Repeat([]byte{'0'}, 64)) },
		"truncated":    func(source *fakePortableExportSource) { source.content = source.content[:len(source.content)-1] },
		"root path": func(source *fakePortableExportSource) {
			source.artifact.Path = "/var/lib/gateway-vpn/secrets/management/link.key"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			source := &fakePortableExportSource{artifact: valid, content: append([]byte(nil), content...)}
			mutate(source)
			root := filepath.Join(t.TempDir(), "exports")
			manager, err := NewRemotePortableManager(source, root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Build(context.Background(), "correct horse battery staple"); err == nil {
				t.Fatal("invalid privileged backup stream was accepted")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed stream left artifacts = %v, %v", entries, err)
			}
		})
	}
}
