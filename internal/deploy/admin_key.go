package deploy

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type AdminIdentity struct {
	PublicKey string
	config    string
	pending   string
}

// PrepareAdminIdentity creates or resumes a protected local administrator key.
// Only its public key is returned; the private key remains in a mode-0600 file
// on the administrative host.
func PrepareAdminIdentity(configPath string) (AdminIdentity, error) {
	if err := prepareAdminConfigPath(configPath); err != nil {
		return AdminIdentity{}, err
	}
	identity := AdminIdentity{config: configPath, pending: configPath + ".pending"}
	if _, err := os.Lstat(configPath); err == nil {
		configuration, loadErr := loadAdminConfig(configPath)
		if loadErr != nil {
			return AdminIdentity{}, loadErr
		}
		identity.PublicKey, loadErr = adminPublicKey(configuration.privateKey)
		return identity, loadErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return AdminIdentity{}, errors.New("inspect administrator WireGuard config failed")
	}
	privateKey, err := loadAdminPending(identity.pending)
	if errors.Is(err, os.ErrNotExist) {
		privateKey, err = createAdminPending(identity.pending)
		if errors.Is(err, os.ErrExist) {
			privateKey, err = loadAdminPending(identity.pending)
		}
	}
	if err != nil {
		return AdminIdentity{}, err
	}
	identity.PublicKey, err = adminPublicKey(privateKey)
	return identity, err
}

// Finalize writes a wg-quick administrator config atomically after the VPS
// public key is known. Existing files must match exactly and are never replaced
// silently.
func (identity AdminIdentity) Finalize(vpsPublicKey, endpoint string) error {
	if identity.config == "" || identity.pending == "" || !validPublicKey(identity.PublicKey) || !validPublicKey(vpsPublicKey) {
		return errors.New("prepared administrator identity and VPS public key are required")
	}
	if _, err := gatewayFinalizeKeyCommandSafe(endpoint, vpsPublicKey); err != nil {
		return err
	}
	if _, err := os.Lstat(identity.config); err == nil {
		existing, loadErr := loadAdminConfig(identity.config)
		if loadErr != nil {
			return loadErr
		}
		publicKey, deriveErr := adminPublicKey(existing.privateKey)
		if deriveErr != nil || publicKey != identity.PublicKey || existing.vpsPublicKey != vpsPublicKey || existing.endpoint != endpoint {
			return errors.New("existing administrator WireGuard config differs from deployment")
		}
		return removeAdminPending(identity.pending)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect administrator WireGuard config failed")
	}
	privateKey, err := loadAdminPending(identity.pending)
	if err != nil {
		return errors.New("pending administrator WireGuard key is unavailable")
	}
	publicKey, err := adminPublicKey(privateKey)
	if err != nil || publicKey != identity.PublicKey {
		return errors.New("pending administrator WireGuard identity changed")
	}
	content := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.80.0.10/32\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 10.80.0.0/24\nPersistentKeepalive = 25\n", privateKey, vpsPublicKey, endpoint)
	temporary, err := os.CreateTemp(filepath.Dir(identity.config), ".gateway-vpn-admin-*.tmp")
	if err != nil {
		return errors.New("create administrator WireGuard config candidate failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("protect administrator WireGuard config candidate failed")
	}
	written, writeErr := io.WriteString(temporary, content)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(content) {
		return errors.New("durably write administrator WireGuard config candidate failed")
	}
	if err := os.Rename(temporaryName, identity.config); err != nil {
		return errors.New("activate administrator WireGuard config failed")
	}
	if err := syncAdminDirectory(filepath.Dir(identity.config)); err != nil {
		return err
	}
	return removeAdminPending(identity.pending)
}

type adminConfig struct {
	privateKey   string
	vpsPublicKey string
	endpoint     string
}

func loadAdminConfig(filename string) (adminConfig, error) {
	content, err := readProtectedAdminFile(filename, 16*1024)
	if err != nil {
		return adminConfig{}, err
	}
	section := ""
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "[Interface]" || line == "[Peer]" {
			section = line
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		identity := section + "\x00" + key
		if !found || section == "" || key == "" || value == "" || values[identity] != "" {
			return adminConfig{}, errors.New("administrator WireGuard config syntax is invalid")
		}
		values[identity] = value
	}
	if scanner.Err() != nil || len(values) != 6 || values["[Interface]\x00Address"] != "10.80.0.10/32" || values["[Peer]\x00AllowedIPs"] != "10.80.0.0/24" || values["[Peer]\x00PersistentKeepalive"] != "25" {
		return adminConfig{}, errors.New("administrator WireGuard config contract is invalid")
	}
	privateKey := values["[Interface]\x00PrivateKey"]
	vpsPublicKey := values["[Peer]\x00PublicKey"]
	endpoint := values["[Peer]\x00Endpoint"]
	if !validPublicKey(privateKey) || !validPublicKey(vpsPublicKey) {
		return adminConfig{}, errors.New("administrator WireGuard config keys are invalid")
	}
	if _, err := gatewayFinalizeKeyCommandSafe(endpoint, vpsPublicKey); err != nil {
		return adminConfig{}, err
	}
	return adminConfig{privateKey: privateKey, vpsPublicKey: vpsPublicKey, endpoint: endpoint}, nil
}

func prepareAdminConfigPath(filename string) error {
	if !filepath.IsAbs(filename) || strings.ContainsAny(filename, "\x00\r\n") || filepath.Clean(filename) != filename {
		return errors.New("absolute administrator WireGuard config path is required")
	}
	directory := filepath.Dir(filename)
	if directory == filepath.Clean(string(os.PathSeparator)) || directory == filename {
		return errors.New("administrator config directory must be a protected real directory")
	}
	if runtime.GOOS == "windows" {
		if err := validateWindowsAdminDirectoryComponents(directory, true); err != nil {
			return err
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return errors.New("create administrator config directory failed")
		}
		if err := validateWindowsAdminDirectoryComponents(directory, false); err != nil {
			return err
		}
		return validateAdminDirectory(directory)
	}

	// Walk from the filesystem root so an existing symlink in any parent
	// component cannot redirect local private-key creation. Missing components
	// are created one at a time with no group/other access. Existing ancestors
	// may be readable. The direct existing parent at the creation boundary must
	// not be writable by another user.
	current := string(os.PathSeparator)
	var parentInfo os.FileInfo
	creating := false
	for _, component := range strings.Split(strings.TrimPrefix(directory, string(os.PathSeparator)), string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("administrator config directory must be a protected real directory")
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if !creating {
				if parentInfo == nil || parentInfo.Mode().Perm()&0o022 != 0 {
					return errors.New("administrator config directory has an unsafe writable ancestor")
				}
				creating = true
			}
			if err := os.Mkdir(current, 0o700); err != nil {
				if !errors.Is(err, os.ErrExist) {
					return errors.New("create administrator config directory failed")
				}
			}
			info, err = os.Lstat(current)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("administrator config directory must be a protected real directory")
		}
		if creating && info.Mode().Perm()&0o077 != 0 {
			return errors.New("administrator config directory must be a protected real directory")
		}
		parentInfo = info
	}
	return validateAdminDirectory(directory)
}

func validateWindowsAdminDirectoryComponents(directory string, allowMissing bool) error {
	volume := filepath.VolumeName(directory)
	if volume == "" {
		return errors.New("administrator config directory must be a protected real directory")
	}
	current := volume + string(os.PathSeparator)
	relative := strings.TrimPrefix(directory, current)
	if relative == directory {
		return errors.New("administrator config directory must be a protected real directory")
	}
	missing := false
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("administrator config directory must be a protected real directory")
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			missing = true
			continue
		}
		if err != nil || missing || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("administrator config directory must be a protected real directory")
		}
	}
	return nil
}

func validateAdminDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("administrator config directory must be a protected real directory")
	}
	return nil
}

func createAdminPending(filename string) (string, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", errors.New("generate administrator WireGuard key failed")
	}
	encoded := base64.StdEncoding.EncodeToString(privateKey.Bytes())
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	written, writeErr := io.WriteString(file, encoded+"\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(encoded)+1 {
		_ = os.Remove(filename)
		return "", errors.New("durably write pending administrator WireGuard key failed")
	}
	if err := syncAdminDirectory(filepath.Dir(filename)); err != nil {
		_ = os.Remove(filename)
		return "", err
	}
	return encoded, nil
}

func loadAdminPending(filename string) (string, error) {
	content, err := readProtectedAdminFile(filename, 256)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(content))
	if !validPublicKey(value) {
		return "", errors.New("pending administrator WireGuard key is invalid")
	}
	return value, nil
}

func readProtectedAdminFile(filename string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("administrator WireGuard file is unsafe")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("read administrator WireGuard file failed")
	}
	return content, nil
}

func removeAdminPending(filename string) error {
	if _, err := os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("inspect pending administrator WireGuard key failed")
	}
	if _, err := loadAdminPending(filename); err != nil {
		return err
	}
	if err := os.Remove(filename); err != nil {
		return errors.New("remove pending administrator WireGuard key failed")
	}
	return syncAdminDirectory(filepath.Dir(filename))
}

func adminPublicKey(privateKey string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(privateKey)
	if err != nil || len(raw) != 32 {
		return "", errors.New("administrator WireGuard private key is invalid")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", errors.New("derive administrator WireGuard public key failed")
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func syncAdminDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return errors.New("open administrator config directory for sync failed")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return errors.New("sync administrator config directory failed")
	}
	return nil
}

func gatewayFinalizeKeyCommandSafe(endpoint, peerPublicKey string) (string, error) {
	if !validPublicKey(peerPublicKey) {
		return "", errors.New("VPS WireGuard public key is invalid")
	}
	if strings.ContainsAny(endpoint, " \t\r\n\x00;&|`$<>(){}[]'\"") {
		return "", errors.New("VPS endpoint is unsafe")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return "", errors.New("VPS endpoint must use HOST:51821")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort != 51821 {
		return "", errors.New("VPS endpoint port must be 51821")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return "", errors.New("VPS endpoint IP must be public global unicast")
		}
	} else if !validDNSName(host) || !strings.Contains(host, ".") {
		return "", errors.New("VPS endpoint hostname is invalid")
	}
	return gatewayFinalizeKeyCommand(endpoint, peerPublicKey), nil
}
