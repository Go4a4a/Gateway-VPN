package networkapply

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gateway-vpn/internal/netutil"
)

const (
	LegacyManifestSchema    = 1
	ManifestSchema          = 2
	OperationLANAddress     = "LAN_ADDRESS"
	OperationEthernetUplink = "ETHERNET_UPLINK"

	EthernetCreate           = "CREATE"
	EthernetReplaceInterface = "REPLACE_INTERFACE"
	EthernetUpdateAddress    = "UPDATE_ADDRESS"
	EthernetDelete           = "DELETE"

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
	SchemaVersion    int               `json:"schema_version"`
	ID               string            `json:"id"`
	OperationKind    string            `json:"operation_kind,omitempty"`
	InterfaceName    string            `json:"interface_name,omitempty"`
	OldLANCIDR       string            `json:"old_lan_cidr,omitempty"`
	NewLANCIDR       string            `json:"new_lan_cidr,omitempty"`
	OldURL           string            `json:"old_url"`
	NewURL           string            `json:"new_url"`
	NewDestinationIP string            `json:"new_destination_ip"`
	Ethernet         *EthernetMutation `json:"ethernet,omitempty"`
	RollbackDeadline string            `json:"rollback_deadline"`
	CreatedAt        string            `json:"created_at"`
}

type EthernetMutation struct {
	Operation                 string   `json:"operation"`
	UplinkID                  string   `json:"uplink_id"`
	ExpectedDesiredGeneration int64    `json:"expected_desired_generation"`
	TargetInterfaceID         string   `json:"target_interface_id"`
	Name                      string   `json:"name,omitempty"`
	AddressMode               string   `json:"address_mode"`
	IPv4CIDR                  string   `json:"ipv4_cidr,omitempty"`
	Gateway                   string   `json:"gateway,omitempty"`
	DNS                       []string `json:"dns"`
	MTU                       int64    `json:"mtu,omitempty"`
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
	if status.Phase != PhaseCreated || !sameManifestCore(previous, manifest) {
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
	if !safeID(manifest.ID) || manifest.OldURL == "" || manifest.NewURL == "" || manifest.NewDestinationIP == "" {
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
	if manifest.SchemaVersion == LegacyManifestSchema {
		if manifest.OperationKind != "" && manifest.OperationKind != OperationLANAddress || manifest.Ethernet != nil {
			return errors.New("legacy LAN transaction manifest contains a foreign operation")
		}
		_, newPrefix, err := validateCandidate(Candidate{
			InterfaceName: manifest.InterfaceName,
			OldLANCIDR:    manifest.OldLANCIDR,
			NewLANCIDR:    manifest.NewLANCIDR,
			OldURL:        manifest.OldURL,
			NewURL:        manifest.NewURL,
		})
		if err != nil || manifest.NewDestinationIP != newPrefix.Addr().String() {
			return errors.New("network transaction LAN candidate is invalid")
		}
		return nil
	}
	if manifest.SchemaVersion != ManifestSchema || manifest.OperationKind != OperationEthernetUplink || manifest.InterfaceName != "" || manifest.OldLANCIDR != "" || manifest.NewLANCIDR != "" || manifest.Ethernet == nil {
		return errors.New("network transaction manifest operation is invalid")
	}
	if err := validateEthernetMutation(*manifest.Ethernet); err != nil {
		return fmt.Errorf("network transaction Ethernet candidate is invalid: %w", err)
	}
	destination, err := netip.ParseAddr(manifest.NewDestinationIP)
	if err != nil || !destination.Is4() {
		return errors.New("network transaction confirmation destination is invalid")
	}
	if err := validateManagementURL(manifest.OldURL, destination); err != nil {
		return errors.New("network transaction old management URL is invalid")
	}
	if err := validateManagementURL(manifest.NewURL, destination); err != nil || manifest.NewURL != manifest.OldURL {
		return errors.New("Ethernet transaction management URL must remain unchanged")
	}
	return nil
}

func validateEthernetMutation(candidate EthernetMutation) error {
	if !safeObjectID(candidate.UplinkID) || !safeObjectID(candidate.TargetInterfaceID) {
		return errors.New("safe uplink and target interface IDs are required")
	}
	switch candidate.Operation {
	case EthernetCreate:
		if candidate.ExpectedDesiredGeneration != 0 || strings.TrimSpace(candidate.Name) == "" || len([]rune(strings.TrimSpace(candidate.Name))) > 128 {
			return errors.New("create requires a name and generation zero")
		}
	case EthernetReplaceInterface, EthernetUpdateAddress:
		if candidate.ExpectedDesiredGeneration < 1 || candidate.Name != "" {
			return errors.New("existing uplink mutation requires its expected generation")
		}
	case EthernetDelete:
		if candidate.ExpectedDesiredGeneration < 1 || candidate.Name != "" {
			return errors.New("delete requires the expected uplink generation")
		}
		if candidate.AddressMode != "" || candidate.IPv4CIDR != "" || candidate.Gateway != "" || len(candidate.DNS) != 0 || candidate.MTU != 0 {
			return errors.New("delete cannot contain Ethernet address configuration")
		}
		return nil
	default:
		return errors.New("unsupported Ethernet operation")
	}
	if candidate.MTU != 0 && (candidate.MTU < 576 || candidate.MTU > 9216) {
		return errors.New("Ethernet MTU must be between 576 and 9216")
	}
	var prefix netip.Prefix
	var gateway netip.Addr
	var err error
	if candidate.IPv4CIDR != "" {
		prefix, err = netip.ParsePrefix(candidate.IPv4CIDR)
		if err != nil || !netutil.IsUsableIPv4Host(prefix, prefix.Addr()) {
			return errors.New("Ethernet IPv4 CIDR is invalid")
		}
	}
	if candidate.Gateway != "" {
		gateway, err = netip.ParseAddr(candidate.Gateway)
		if err != nil || !gateway.Is4() || gateway.IsUnspecified() {
			return errors.New("Ethernet gateway is invalid")
		}
	}
	switch candidate.AddressMode {
	case "DHCP":
		if prefix.IsValid() || gateway.IsValid() {
			return errors.New("DHCP cannot contain a static address or gateway")
		}
	case "STATIC":
		if !prefix.IsValid() || !gateway.IsValid() || !netutil.IsUsableIPv4Host(prefix, gateway) || prefix.Addr() == gateway {
			return errors.New("static mode requires an address and a different gateway in the same subnet")
		}
	default:
		return errors.New("Ethernet address mode must be DHCP or STATIC")
	}
	if len(candidate.DNS) > 8 {
		return errors.New("at most eight Ethernet DNS addresses are allowed")
	}
	seen := make(map[string]struct{}, len(candidate.DNS))
	for _, raw := range candidate.DNS {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.IsUnspecified() {
			return errors.New("Ethernet DNS contains an invalid IPv4 address")
		}
		if _, duplicate := seen[address.String()]; duplicate {
			return errors.New("Ethernet DNS contains a duplicate address")
		}
		seen[address.String()] = struct{}{}
	}
	return nil
}

func safeObjectID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-_:.", character) {
			continue
		}
		return false
	}
	return true
}

func sameManifestCore(left, right Manifest) bool {
	left.RollbackDeadline, left.CreatedAt = "", ""
	right.RollbackDeadline, right.CreatedAt = "", ""
	leftPayload, leftErr := json.Marshal(left)
	rightPayload, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
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
