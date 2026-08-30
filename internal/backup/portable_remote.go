package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// PortableExportSource returns only an encrypted Gateway backup stream and
// path-free authenticated metadata. Production uses the root broker because
// the control-plane user must not be able to traverse root-owned secret trees.
type PortableExportSource interface {
	ExportPortableBackup(context.Context, string) (PortableArtifact, io.ReadCloser, error)
}

// RemotePortableManager materializes the already-encrypted broker stream in a
// control-plane-owned temporary artifact so the existing WebUI can verify and
// download it. Plaintext archive entries never cross this boundary.
type RemotePortableManager struct {
	Source     PortableExportSource
	ExportRoot string
	mutex      sync.Mutex
}

func NewRemotePortableManager(source PortableExportSource, exportRoot string) (*RemotePortableManager, error) {
	if source == nil || !filepath.IsAbs(exportRoot) {
		return nil, errors.New("portable backup source and absolute export root are required")
	}
	return &RemotePortableManager{Source: source, ExportRoot: filepath.Clean(exportRoot)}, nil
}

func (manager *RemotePortableManager) Build(ctx context.Context, passphrase string) (PortableArtifact, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if err := ValidatePassphrase(passphrase); err != nil {
		return PortableArtifact{}, err
	}
	if err := secureDirectory(manager.ExportRoot); err != nil {
		return PortableArtifact{}, err
	}
	artifact, source, err := manager.Source.ExportPortableBackup(ctx, passphrase)
	if err != nil {
		return PortableArtifact{}, err
	}
	defer source.Close()
	if err := ValidatePortableArtifactMetadata(artifact); err != nil {
		return PortableArtifact{}, err
	}
	finalPath := filepath.Join(manager.ExportRoot, artifact.Filename)
	file, err := os.OpenFile(finalPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return PortableArtifact{}, errors.New("create encrypted broker backup artifact failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = file.Close()
			_ = os.Remove(finalPath)
		}
	}()
	hash := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(file, hash), source, artifact.Bytes)
	var trailing [1]byte
	extra, trailingErr := source.Read(trailing[:])
	if copyErr != nil || written != artifact.Bytes || extra != 0 || !errors.Is(trailingErr, io.EOF) || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return PortableArtifact{}, errors.New("encrypted broker backup stream failed verification")
	}
	if err := file.Sync(); err != nil {
		return PortableArtifact{}, errors.New("sync encrypted broker backup artifact failed")
	}
	if err := file.Close(); err != nil {
		return PortableArtifact{}, errors.New("close encrypted broker backup artifact failed")
	}
	if err := syncDirectory(manager.ExportRoot); err != nil {
		return PortableArtifact{}, err
	}
	artifact.Path = finalPath
	committed = true
	return artifact, nil
}

func (manager *RemotePortableManager) Open(artifact PortableArtifact) (io.ReadCloser, error) {
	store := PortableManager{ExportRoot: manager.ExportRoot}
	return store.Open(artifact)
}

func (manager *RemotePortableManager) Remove(artifact PortableArtifact) error {
	store := PortableManager{ExportRoot: manager.ExportRoot}
	return store.Remove(artifact)
}
