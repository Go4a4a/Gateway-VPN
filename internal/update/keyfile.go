package update

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	EncryptedKeyFileFormatVersion = 1
	MaximumEncryptedKeyFileBytes  = int64(64 << 10)

	encryptedKeyHeaderMaximum  = 4 << 10
	encryptedKeyKDFMemoryKiB   = 64 * 1024
	encryptedKeyKDFIterations  = 3
	encryptedKeyKDFParallelism = 2
	minimumKeyPassphraseRunes  = 10
	maximumKeyPassphraseBytes  = 256
	encryptedKeySaltBytes      = 16
	encryptedKeyNonceBytes     = 12
	encryptedKeyFileExtension  = ".gvkey"
	encryptedKeyMagic          = "GATEWAY-VPN-KEY1"
)

type EncryptedKeyFileInfo struct {
	Fingerprint string
	Bytes       int64
	SHA256      string
}

type encryptedKeyHeader struct {
	FormatVersion  int    `json:"format_version"`
	PayloadFormat  string `json:"payload_format"`
	Cipher         string `json:"cipher"`
	KDF            string `json:"kdf"`
	KDFMemoryKiB   uint32 `json:"kdf_memory_kib"`
	KDFIterations  uint32 `json:"kdf_iterations"`
	KDFParallelism uint8  `json:"kdf_parallelism"`
	Salt           string `json:"salt_base64"`
	Nonce          string `json:"nonce_base64"`
}

type encryptedKeyPayload struct {
	FormatVersion int    `json:"format_version"`
	Algorithm     string `json:"algorithm"`
	PrivatePKCS8  []byte `json:"private_key_pkcs8_der"`
	PublicPKIX    []byte `json:"public_key_pkix_der"`
	Fingerprint   string `json:"public_key_sha256"`
}

type decryptedEncryptedKey struct {
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	fingerprint string
	raw         []byte
}

func ValidateEncryptedKeyPassphrase(passphrase []byte) error {
	if !utf8.Valid(passphrase) || utf8.RuneCount(passphrase) < minimumKeyPassphraseRunes || len(passphrase) > maximumKeyPassphraseBytes ||
		bytes.IndexByte(passphrase, 0) >= 0 || bytes.IndexByte(passphrase, '\n') >= 0 || bytes.IndexByte(passphrase, '\r') >= 0 ||
		len(bytes.TrimSpace(passphrase)) != len(passphrase) {
		return fmt.Errorf("encrypted release key passphrase must contain at least %d UTF-8 characters and at most %d bytes without leading/trailing whitespace or line breaks", minimumKeyPassphraseRunes, maximumKeyPassphraseBytes)
	}
	return nil
}

func CreateEncryptedKeyFile(filename string, passphrase []byte) (EncryptedKeyFileInfo, error) {
	directory, filename, err := validateEncryptedKeyDestination(filename)
	if err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	if err := ValidateEncryptedKeyPassphrase(passphrase); err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return EncryptedKeyFileInfo{}, errors.New("generate encrypted Ed25519 release key failed")
	}
	defer clear(privateKey)
	raw, fingerprint, err := marshalEncryptedKeyFile(privateKey, publicKey, passphrase)
	if err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	defer clear(raw)
	if err := writeExclusive(filename, raw, 0o600); err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	cleanup := func() {
		_ = os.Remove(filename)
		_ = syncDirectory(directory)
	}
	if err := syncDirectory(directory); err != nil {
		cleanup()
		return EncryptedKeyFileInfo{}, errors.New("sync encrypted release key directory failed")
	}
	info, err := VerifyEncryptedKeyFile(filename, passphrase)
	if err != nil || info.Fingerprint != fingerprint {
		cleanup()
		return EncryptedKeyFileInfo{}, errors.New("verify written encrypted release key failed")
	}
	return info, nil
}

func VerifyEncryptedKeyFile(filename string, passphrase []byte) (EncryptedKeyFileInfo, error) {
	loaded, err := loadEncryptedKeyFile(filename, passphrase)
	if err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	defer loaded.clear()
	digest := sha256.Sum256(loaded.raw)
	return EncryptedKeyFileInfo{
		Fingerprint: loaded.fingerprint,
		Bytes:       int64(len(loaded.raw)),
		SHA256:      hex.EncodeToString(digest[:]),
	}, nil
}

func BackupEncryptedKeyFile(sourcePath, backupPath string, passphrase []byte) (EncryptedKeyFileInfo, error) {
	sourcePath, err := validateEncryptedKeySource(sourcePath)
	if err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	directory, backupPath, err := validateEncryptedKeyDestination(backupPath)
	if err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	if sameFilesystemPath(sourcePath, backupPath) || sameFilesystemPath(filepath.Dir(sourcePath), directory) {
		return EncryptedKeyFileInfo{}, errors.New("encrypted release key backup must use a different destination directory")
	}
	loaded, err := loadEncryptedKeyFile(sourcePath, passphrase)
	if err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	defer loaded.clear()
	if err := writeExclusive(backupPath, loaded.raw, 0o600); err != nil {
		return EncryptedKeyFileInfo{}, err
	}
	cleanup := func() {
		_ = os.Remove(backupPath)
		_ = syncDirectory(directory)
	}
	if err := syncDirectory(directory); err != nil {
		cleanup()
		return EncryptedKeyFileInfo{}, errors.New("sync encrypted release key backup directory failed")
	}
	backup, err := VerifyEncryptedKeyFile(backupPath, passphrase)
	if err != nil || backup.Fingerprint != loaded.fingerprint {
		cleanup()
		return EncryptedKeyFileInfo{}, errors.New("verify encrypted release key backup failed")
	}
	digest := sha256.Sum256(loaded.raw)
	if backup.SHA256 != hex.EncodeToString(digest[:]) || backup.Bytes != int64(len(loaded.raw)) {
		cleanup()
		return EncryptedKeyFileInfo{}, errors.New("encrypted release key backup differs from its source")
	}
	return backup, nil
}

func UnlockEncryptedKeyFile(filename string, passphrase []byte, privatePath, publicPath string) (string, error) {
	directory, privatePath, publicPath, err := validateKeyPairDestinationPaths(privatePath, publicPath)
	if err != nil {
		return "", err
	}
	loaded, err := loadEncryptedKeyFile(filename, passphrase)
	if err != nil {
		return "", err
	}
	defer loaded.clear()
	fingerprint, err := writeVerifiedKeyPair(directory, privatePath, publicPath, loaded.privateKey, loaded.publicKey)
	if err != nil {
		return "", err
	}
	if fingerprint != loaded.fingerprint {
		_ = os.Remove(publicPath)
		_ = os.Remove(privatePath)
		_ = syncDirectory(directory)
		return "", errors.New("unlocked release signing identity fingerprint changed")
	}
	return fingerprint, nil
}

func marshalEncryptedKeyFile(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, passphrase []byte) ([]byte, string, error) {
	if err := ValidateEncryptedKeyPassphrase(passphrase); err != nil {
		return nil, "", err
	}
	if len(privateKey) != ed25519.PrivateKeySize || len(publicKey) != ed25519.PublicKeySize || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return nil, "", errors.New("valid matching Ed25519 release key pair is required")
	}
	fingerprint, err := PublicKeyFingerprint(publicKey)
	if err != nil {
		return nil, "", err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", errors.New("encode encrypted release private key failed")
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", errors.New("encode encrypted release public key failed")
	}
	payload, err := json.Marshal(encryptedKeyPayload{
		FormatVersion: EncryptedKeyFileFormatVersion,
		Algorithm:     "Ed25519",
		PrivatePKCS8:  privateDER,
		PublicPKIX:    publicDER,
		Fingerprint:   fingerprint,
	})
	if err != nil {
		return nil, "", errors.New("encode encrypted release key payload failed")
	}
	defer clear(payload)
	salt := make([]byte, encryptedKeySaltBytes)
	nonce := make([]byte, encryptedKeyNonceBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, "", errors.New("generate encrypted release key salt failed")
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", errors.New("generate encrypted release key nonce failed")
	}
	headerContent, err := json.Marshal(encryptedKeyHeader{
		FormatVersion:  EncryptedKeyFileFormatVersion,
		PayloadFormat:  "ed25519-pkcs8-json",
		Cipher:         "AES-256-GCM",
		KDF:            "argon2id",
		KDFMemoryKiB:   encryptedKeyKDFMemoryKiB,
		KDFIterations:  encryptedKeyKDFIterations,
		KDFParallelism: encryptedKeyKDFParallelism,
		Salt:           base64.RawStdEncoding.EncodeToString(salt),
		Nonce:          base64.RawStdEncoding.EncodeToString(nonce),
	})
	if err != nil || len(headerContent) == 0 || len(headerContent) > encryptedKeyHeaderMaximum {
		return nil, "", errors.New("encode encrypted release key header failed")
	}
	prefix := make([]byte, 0, len(encryptedKeyMagic)+4+len(headerContent))
	prefix = append(prefix, encryptedKeyMagic...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(headerContent)))
	prefix = append(prefix, length...)
	prefix = append(prefix, headerContent...)
	key := argon2.IDKey(passphrase, salt, encryptedKeyKDFIterations, encryptedKeyKDFMemoryKiB, encryptedKeyKDFParallelism, 32)
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, "", errors.New("initialize encrypted release key cipher failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", errors.New("initialize encrypted release key authentication failed")
	}
	ciphertext := aead.Seal(nil, nonce, payload, prefix)
	if len(prefix)+len(ciphertext) > int(MaximumEncryptedKeyFileBytes) {
		return nil, "", errors.New("encrypted release key file exceeds its bound")
	}
	return append(prefix, ciphertext...), fingerprint, nil
}

func loadEncryptedKeyFile(filename string, passphrase []byte) (decryptedEncryptedKey, error) {
	if err := ValidateEncryptedKeyPassphrase(passphrase); err != nil {
		return decryptedEncryptedKey{}, err
	}
	filename, err := validateEncryptedKeySource(filename)
	if err != nil {
		return decryptedEncryptedKey{}, err
	}
	raw, err := readBoundedRegular(filename, MaximumEncryptedKeyFileBytes)
	if err != nil {
		return decryptedEncryptedKey{}, errors.New("encrypted release key file is invalid")
	}
	failed := func() (decryptedEncryptedKey, error) {
		clear(raw)
		return decryptedEncryptedKey{}, errors.New("encrypted release key passphrase or file is invalid")
	}
	if len(raw) <= len(encryptedKeyMagic)+4 || !bytes.Equal(raw[:len(encryptedKeyMagic)], []byte(encryptedKeyMagic)) {
		return failed()
	}
	headerLength := int(binary.BigEndian.Uint32(raw[len(encryptedKeyMagic) : len(encryptedKeyMagic)+4]))
	headerOffset := len(encryptedKeyMagic) + 4
	if headerLength <= 0 || headerLength > encryptedKeyHeaderMaximum || headerOffset+headerLength >= len(raw) {
		return failed()
	}
	headerContent := raw[headerOffset : headerOffset+headerLength]
	var header encryptedKeyHeader
	if err := decodeStrict(headerContent, &header); err != nil ||
		header.FormatVersion != EncryptedKeyFileFormatVersion || header.PayloadFormat != "ed25519-pkcs8-json" ||
		header.Cipher != "AES-256-GCM" || header.KDF != "argon2id" ||
		header.KDFMemoryKiB != encryptedKeyKDFMemoryKiB || header.KDFIterations != encryptedKeyKDFIterations || header.KDFParallelism != encryptedKeyKDFParallelism {
		return failed()
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(header.Salt)
	nonce, nonceErr := base64.RawStdEncoding.DecodeString(header.Nonce)
	if saltErr != nil || nonceErr != nil || len(salt) != encryptedKeySaltBytes || len(nonce) != encryptedKeyNonceBytes {
		return failed()
	}
	key := argon2.IDKey(passphrase, salt, header.KDFIterations, header.KDFMemoryKiB, header.KDFParallelism, 32)
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return failed()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return failed()
	}
	prefixEnd := headerOffset + headerLength
	ciphertext := raw[prefixEnd:]
	if len(ciphertext) <= aead.Overhead() {
		return failed()
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, raw[:prefixEnd])
	if err != nil {
		return failed()
	}
	defer clear(plaintext)
	var payload encryptedKeyPayload
	defer func() {
		clear(payload.PrivatePKCS8)
		payload.PrivatePKCS8 = nil
	}()
	if err := decodeStrict(plaintext, &payload); err != nil || payload.FormatVersion != EncryptedKeyFileFormatVersion || payload.Algorithm != "Ed25519" ||
		len(payload.PrivatePKCS8) == 0 || len(payload.PrivatePKCS8) > 4<<10 || len(payload.PublicPKIX) == 0 || len(payload.PublicPKIX) > 4<<10 {
		return failed()
	}
	parsedPrivate, err := x509.ParsePKCS8PrivateKey(payload.PrivatePKCS8)
	if err != nil {
		return failed()
	}
	privateKey, ok := parsedPrivate.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return failed()
	}
	parsedPublic, err := x509.ParsePKIXPublicKey(payload.PublicPKIX)
	if err != nil {
		clear(privateKey)
		return failed()
	}
	publicKey, ok := parsedPublic.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		clear(privateKey)
		return failed()
	}
	fingerprint, err := PublicKeyFingerprint(publicKey)
	if err != nil || payload.Fingerprint != fingerprint {
		clear(privateKey)
		return failed()
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	clear(privateKey)
	return decryptedEncryptedKey{
		privateKey:  privateCopy,
		publicKey:   append(ed25519.PublicKey(nil), publicKey...),
		fingerprint: fingerprint,
		raw:         raw,
	}, nil
}

func (loaded *decryptedEncryptedKey) clear() {
	clear(loaded.privateKey)
	clear(loaded.publicKey)
	clear(loaded.raw)
	loaded.privateKey = nil
	loaded.publicKey = nil
	loaded.fingerprint = ""
	loaded.raw = nil
}

func validateEncryptedKeyDestination(filename string) (string, string, error) {
	if !filepath.IsAbs(filename) {
		return "", "", errors.New("absolute encrypted release key file path is required")
	}
	filename = filepath.Clean(filename)
	if !strings.EqualFold(filepath.Ext(filename), encryptedKeyFileExtension) {
		return "", "", errors.New("encrypted release key file must use the .gvkey extension")
	}
	directory := filepath.Dir(filename)
	if err := validateEncryptedKeyDirectory(directory); err != nil {
		return "", "", err
	}
	return directory, filename, nil
}

func validateEncryptedKeySource(filename string) (string, error) {
	_, filename, err := validateEncryptedKeyDestination(filename)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= int64(len(encryptedKeyMagic)+4) || info.Size() > MaximumEncryptedKeyFileBytes {
		return "", errors.New("encrypted release key must be a bounded regular non-symlink file")
	}
	if runtime.GOOS != "windows" {
		resolved, err := filepath.EvalSymlinks(filename)
		if err != nil || !sameFilesystemPath(filepath.Clean(resolved), filename) {
			return "", errors.New("encrypted release key path must not contain symlink components")
		}
	}
	return filename, nil
}

func validateEncryptedKeyDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("encrypted release key destination must be an existing real directory")
	}
	if runtime.GOOS != "windows" {
		resolved, err := filepath.EvalSymlinks(directory)
		if err != nil || !sameFilesystemPath(filepath.Clean(resolved), directory) {
			return errors.New("encrypted release key destination must not contain symlink components")
		}
	}
	for current := directory; ; current = filepath.Dir(current) {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return errors.New("encrypted release key files must not be stored inside a Git worktree")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("inspect encrypted release key destination ancestors failed")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}
