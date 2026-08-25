package distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ArtifactFromFile turns one locally built regular file into the exact
// hash/size record that will be authenticated by the channel manifest.
func ArtifactFromFile(role, operatingSystem, architecture, filename, version string) (Artifact, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumArtifactBytes {
		return Artifact{}, errors.New("channel artifact source must be a bounded regular non-symlink file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return Artifact{}, errors.New("open channel artifact source failed")
	}
	openedInfo, statErr := file.Stat()
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, MaximumArtifactBytes+1))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, openedInfo) || copyErr != nil || closeErr != nil || written != info.Size() {
		return Artifact{}, errors.New("channel artifact changed while it was hashed")
	}
	mediaType := "application/octet-stream"
	if role == RoleGateway || role == RoleVPS {
		mediaType = "application/gzip"
	}
	artifact := Artifact{
		Role: role, OS: operatingSystem, Arch: architecture,
		Filename: filepath.Base(filename), SHA256: hex.EncodeToString(hash.Sum(nil)),
		Bytes: written, MediaType: mediaType,
	}
	if err := validateArtifact(artifact, version); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}
