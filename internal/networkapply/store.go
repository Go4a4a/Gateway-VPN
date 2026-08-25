package networkapply

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	ManifestSchema  = 1
	PhaseCreated    = "CREATED"
	PhaseSnapshot   = "SNAPSHOT_READY"
	PhaseArmed      = "ARMED"
	PhaseApplied    = "APPLIED"
	PhaseConfirming = "CONFIRMING"
	PhaseConfirmed  = "CONFIRMED"
	PhaseRolledBack = "ROLLED_BACK"
	PhaseFailed     = "FAILED"
)

type Manifest struct {
	SchemaVersion    int    `json:"schema_version"`
	ID               string `json:"id"`
	InterfaceName    string `json:"interface_name"`
	OldLANCIDR       string `json:"old_lan_cidr"`
	NewLANCIDR       string `json:"new_lan_cidr"`
	OldURL           string `json:"old_url"`
	NewURL           string `json:"new_url"`
	NewDestinationIP string `json:"new_destination_ip"`
	RollbackDeadline string `json:"rollback_deadline"`
	CreatedAt        string `json:"created_at"`
}

type Status struct {
	Phase     string `json:"phase"`
	UpdatedAt string `json:"updated_at"`
}

type manifestEnvelope struct {
	Manifest Manifest `json:"manifest"`
	SHA256   string   `json:"sha256"`
}

type DiskStore struct {
	Root string
	Now  func() time.Time
}

func (store DiskStore) Create(manifest Manifest) (string, error) {
	if err := validateManifest(manifest); err != nil {
		return "", err
	}
	root, err := filepath.Abs(store.Root)
	if err != nil || strings.TrimSpace(store.Root) == "" {
		return "", errors.New("network transaction root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create network transaction root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", fmt.Errorf("secure network transaction root: %w", err)
	}
	destination := filepath.Join(root, manifest.ID)
	if _, err := os.Lstat(destination); err == nil {
		return "", errors.New("network transaction directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect network transaction directory: %w", err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return "", fmt.Errorf("create network transaction directory: %w", err)
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		return "", fmt.Errorf("secure network transaction directory: %w", err)
	}
	envelope, err := encodeManifestEnvelope(manifest)
	if err != nil {
		return "", fmt.Errorf("encode network transaction envelope: %w", err)
	}
	if err := atomicWrite(filepath.Join(destination, "manifest.json"), envelope, 0o600); err != nil {
		return "", fmt.Errorf("write network transaction manifest: %w", err)
	}
	if err := store.SetPhase(manifest.ID, PhaseCreated); err != nil {
		return "", err
	}
	if err := syncDirectory(destination); err != nil {
		return "", fmt.Errorf("sync network transaction directory: %w", err)
	}
	return destination, nil
}

func (store DiskStore) ReplaceManifest(manifest Manifest) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	previous, status, err := store.Load(manifest.ID)
	if err != nil {
		return err
	}
	if status.Phase != PhaseCreated || previous.ID != manifest.ID || previous.InterfaceName != manifest.InterfaceName || previous.OldLANCIDR != manifest.OldLANCIDR || previous.NewLANCIDR != manifest.NewLANCIDR || previous.OldURL != manifest.OldURL || previous.NewURL != manifest.NewURL || previous.NewDestinationIP != manifest.NewDestinationIP {
		return errors.New("network transaction manifest replacement is not allowed")
	}
	payload, err := encodeManifestEnvelope(manifest)
	if err != nil {
		return err
	}
	directory, err := store.Directory(manifest.ID)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(directory, "manifest.json"), payload, 0o600); err != nil {
		return fmt.Errorf("replace network transaction manifest: %w", err)
	}
	return syncDirectory(directory)
}

func (store DiskStore) Directory(id string) (string, error) {
	if !safeID(id) || strings.TrimSpace(store.Root) == "" {
		return "", errors.New("safe network transaction id and root are required")
	}
	root, err := filepath.Abs(store.Root)
	if err != nil {
		return "", errors.New("resolve network transaction root failed")
	}
	return filepath.Join(root, id), nil
}

func (store DiskStore) Load(id string) (Manifest, Status, error) {
	directory, err := store.Directory(id)
	if err != nil {
		return Manifest{}, Status{}, err
	}
	manifestPayload, err := readBoundedRegular(filepath.Join(directory, "manifest.json"), 64<<10)
	if err != nil {
		return Manifest{}, Status{}, fmt.Errorf("read network transaction manifest: %w", err)
	}
	var envelope manifestEnvelope
	if err := decodeStrictJSON(manifestPayload, &envelope); err != nil {
		return Manifest{}, Status{}, fmt.Errorf("decode network transaction manifest: %w", err)
	}
	encodedManifest, err := json.Marshal(envelope.Manifest)
	if err != nil {
		return Manifest{}, Status{}, err
	}
	digest := sha256.Sum256(encodedManifest)
	if envelope.SHA256 == "" || !equalHexDigest(envelope.SHA256, digest[:]) {
		return Manifest{}, Status{}, errors.New("network transaction manifest checksum mismatch")
	}
	if err := validateManifest(envelope.Manifest); err != nil || envelope.Manifest.ID != id {
		return Manifest{}, Status{}, errors.New("network transaction manifest is invalid")
	}
	statusPayload, err := readBoundedRegular(filepath.Join(directory, "status.json"), 4<<10)
	if err != nil {
		return Manifest{}, Status{}, fmt.Errorf("read network transaction status: %w", err)
	}
	var status Status
	if err := decodeStrictJSON(statusPayload, &status); err != nil || !validPhase(status.Phase) {
		return Manifest{}, Status{}, errors.New("network transaction status is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, status.UpdatedAt); err != nil {
		return Manifest{}, Status{}, errors.New("network transaction status timestamp is invalid")
	}
	return envelope.Manifest, status, nil
}

func (store DiskStore) SetPhase(id, phase string) error {
	if !validPhase(phase) {
		return errors.New("network transaction phase is invalid")
	}
	directory, err := store.Directory(id)
	if err != nil {
		return err
	}
	now := time.Now
	if store.Now != nil {
		now = store.Now
	}
	payload, err := json.Marshal(Status{Phase: phase, UpdatedAt: now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(directory, "status.json"), payload, 0o600); err != nil {
		return fmt.Errorf("write network transaction status: %w", err)
	}
	return syncDirectory(directory)
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchema || !safeID(manifest.ID) || !validInterfaceName(manifest.InterfaceName) || manifest.OldLANCIDR == "" || manifest.NewLANCIDR == "" || manifest.OldURL == "" || manifest.NewURL == "" || manifest.NewDestinationIP == "" {
		return errors.New("complete network transaction manifest is required")
	}
	deadline, err := time.Parse(time.RFC3339Nano, manifest.RollbackDeadline)
	if err != nil {
		return errors.New("network transaction rollback deadline is invalid")
	}
	created, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt)
	if err != nil || !deadline.After(created) || deadline.Sub(created) > 90*time.Second {
		return errors.New("network transaction deadline must be after creation and at most 90 seconds")
	}
	_, newPrefix, err := validateCandidate(Candidate{
		InterfaceName: manifest.InterfaceName,
		OldLANCIDR:    manifest.OldLANCIDR,
		NewLANCIDR:    manifest.NewLANCIDR,
		OldURL:        manifest.OldURL,
		NewURL:        manifest.NewURL,
	})
	if err != nil || manifest.NewDestinationIP != newPrefix.Addr().String() {
		return errors.New("network transaction manifest candidate is invalid")
	}
	return nil
}

func validPhase(value string) bool {
	switch value {
	case PhaseCreated, PhaseSnapshot, PhaseArmed, PhaseApplied, PhaseConfirming, PhaseConfirmed, PhaseRolledBack, PhaseFailed:
		return true
	default:
		return false
	}
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_.:-", char) {
			continue
		}
		return false
	}
	return true
}

func atomicWrite(destination string, payload []byte, mode os.FileMode) error {
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".transaction-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
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
	if err := os.Rename(temporaryName, destination); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		if removeErr := os.Remove(destination); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if retryErr := os.Rename(temporaryName, destination); retryErr != nil {
			return retryErr
		}
	}
	return nil
}

func readBoundedRegular(filename string, limit int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, errors.New("file is missing, unsafe, or too large")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, errors.New("file read failed or exceeded limit")
	}
	return content, nil
}

func decodeStrictJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func equalHexDigest(encoded string, digest []byte) bool {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(digest) {
		return false
	}
	return bytes.Equal(decoded, digest)
}

func encodeManifestEnvelope(manifest Manifest) ([]byte, error) {
	encodedManifest, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode network transaction manifest: %w", err)
	}
	digest := sha256.Sum256(encodedManifest)
	envelope, err := json.Marshal(manifestEnvelope{Manifest: manifest, SHA256: hex.EncodeToString(digest[:])})
	if err != nil {
		return nil, fmt.Errorf("encode network transaction envelope: %w", err)
	}
	return envelope, nil
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
