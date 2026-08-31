package update

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	RestorePointFormatVersion = 1
	RestorePointKindPreUpdate = "PRE_UPDATE"
	maximumRestorePointFiles  = 4096
	maximumRestorePointBytes  = int64(4 << 30)
)

var restorePointIDPattern = regexp.MustCompile(`^point-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{24}$`)

func ValidateRestorePointID(value string) error {
	if !restorePointIDPattern.MatchString(value) {
		return errors.New("restore point id is invalid")
	}
	return nil
}

type RestorePointFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type RestorePointManifest struct {
	FormatVersion          int                `json:"format_version"`
	PointID                string             `json:"point_id"`
	Kind                   string             `json:"kind"`
	CreatedAt              string             `json:"created_at"`
	GatewayVersion         string             `json:"gateway_version"`
	SchemaVersion          int64              `json:"schema_version"`
	ReleaseTarget          string             `json:"release_target"`
	ReleaseManifestSHA256  string             `json:"release_manifest_sha256"`
	SignerKeySHA256        string             `json:"signer_key_sha256"`
	HostContractSHA256     string             `json:"host_contract_sha256"`
	MihomoActiveGeneration string             `json:"mihomo_active_generation,omitempty"`
	Files                  []RestorePointFile `json:"files"`
	TotalBytes             int64              `json:"total_bytes"`
	Verification           string             `json:"verification"`
}

type RestorePoint struct {
	Manifest            RestorePointManifest `json:"manifest"`
	Protected           bool                 `json:"protected"`
	Roles               []string             `json:"roles"`
	Compatible          bool                 `json:"compatible"`
	CompatibilityReason string               `json:"compatibility_reason"`
}

type RestorePointPolicy struct {
	MaximumPoints    int
	MaximumBytes     int64
	MaximumAge       time.Duration
	MinimumOldPoints int
}

func DefaultRestorePointPolicy() RestorePointPolicy {
	return RestorePointPolicy{MaximumPoints: 4, MaximumBytes: 8 << 30, MaximumAge: 365 * 24 * time.Hour, MinimumOldPoints: 2}
}

type RestorePointStore struct {
	Root          string
	ReleaseRoot   string
	StateDir      string
	Configuration string
	Verification  VerificationPolicy
	Now           func() time.Time
}

func (store *RestorePointStore) CreatePreUpdate(ctx context.Context, version string, schema int64, snapshotDatabase string) (RestorePoint, error) {
	if err := store.validate(); err != nil {
		return RestorePoint{}, err
	}
	if ValidateGatewayVersion(version) != nil || schema < 1 || !filepath.IsAbs(snapshotDatabase) {
		return RestorePoint{}, errors.New("restore point version, schema, or database path is invalid")
	}
	releaseTarget := "releases/v" + version
	releaseRoot := filepath.Join(store.ReleaseRoot, filepath.FromSlash(releaseTarget))
	verified, err := VerifyRelease(releaseRoot, store.verificationFor(version, schema))
	if err != nil || verified.Release.GatewayVersion != version {
		return RestorePoint{}, errors.New("restore point release is not the expected signed artifact")
	}
	releaseManifestSHA, _, err := hashFile(filepath.Join(releaseRoot, ManifestFilename), MaximumManifestBytes)
	if err != nil {
		return RestorePoint{}, errors.New("hash restore point release manifest failed")
	}
	mihomoActiveGeneration, err := inspectMihomoActiveGeneration(store.StateDir)
	if err != nil {
		return RestorePoint{}, fmt.Errorf("inspect restore point Mihomo generation: %w", err)
	}
	id, err := newRestorePointID(store.now())
	if err != nil {
		return RestorePoint{}, err
	}
	if err := secureRealDirectory(store.Root, 0o700); err != nil {
		return RestorePoint{}, err
	}
	temporary := filepath.Join(store.Root, "."+id+".tmp")
	final := filepath.Join(store.Root, id)
	if pathExists(temporary) || pathExists(final) {
		return RestorePoint{}, errors.New("restore point identity collision")
	}
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return RestorePoint{}, err
	}
	defer removeRestorePointTemporary(store.Root, temporary)
	files := make([]RestorePointFile, 0, 128)
	add := func(source, relative string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !safeRelativePath(relative) || len(files) >= maximumRestorePointFiles {
			return errors.New("restore point file path or count exceeds its bound")
		}
		target := filepath.Join(temporary, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := copyExclusiveFile(source, target, 0o600, MaximumFileBytes); err != nil {
			return err
		}
		digest, size, err := hashFile(target, MaximumFileBytes)
		if err != nil || size <= 0 {
			return errors.New("hash restore point file failed")
		}
		files = append(files, RestorePointFile{Path: relative, Bytes: size, SHA256: digest})
		return nil
	}
	if err := add(snapshotDatabase, "database/state.db"); err != nil {
		return RestorePoint{}, fmt.Errorf("copy restore point database: %w", err)
	}
	if err := add(store.Configuration, "config/config.yaml"); err != nil {
		return RestorePoint{}, fmt.Errorf("copy restore point configuration: %w", err)
	}
	for _, item := range []struct{ source, target string }{
		{filepath.Join(store.StateDir, "secrets"), "state/secrets"},
		{filepath.Join(store.StateDir, "subscriptions"), "state/subscriptions"},
		{filepath.Join(store.StateDir, "tls"), "state/tls"},
		{filepath.Join(store.StateDir, "mihomo", "generations"), "state/mihomo/generations"},
		{filepath.Join(store.StateDir, "mihomo", "state"), "state/mihomo/state"},
	} {
		if err := copyRestorePointTree(ctx, item.source, item.target, add); err != nil {
			return RestorePoint{}, err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var total int64
	for index, file := range files {
		if index > 0 && files[index-1].Path >= file.Path || total > maximumRestorePointBytes-file.Bytes {
			return RestorePoint{}, errors.New("restore point files are unsorted, duplicated, or oversized")
		}
		total += file.Bytes
	}
	manifest := RestorePointManifest{
		FormatVersion: RestorePointFormatVersion, PointID: id, Kind: RestorePointKindPreUpdate,
		CreatedAt: store.now().Format(time.RFC3339Nano), GatewayVersion: version, SchemaVersion: schema,
		ReleaseTarget: releaseTarget, ReleaseManifestSHA256: releaseManifestSHA,
		SignerKeySHA256: verified.Fingerprint, HostContractSHA256: verified.Release.HostContractSHA256,
		MihomoActiveGeneration: mihomoActiveGeneration,
		Files:                  files, TotalBytes: total, Verification: "PASS",
	}
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return RestorePoint{}, err
	}
	content = append(content, '\n')
	digest := sha256.Sum256(content)
	if err := writeExclusive(filepath.Join(temporary, "manifest.json"), content, 0o600); err != nil {
		return RestorePoint{}, err
	}
	if err := writeExclusive(filepath.Join(temporary, "manifest.sha256"), []byte(hex.EncodeToString(digest[:])+"\n"), 0o600); err != nil {
		return RestorePoint{}, err
	}
	if err := syncTree(temporary); err != nil {
		return RestorePoint{}, err
	}
	if _, err := store.verifyDirectory(ctx, temporary, id); err != nil {
		return RestorePoint{}, err
	}
	if err := os.Rename(temporary, final); err != nil {
		return RestorePoint{}, err
	}
	if err := syncDirectoryPath(store.Root); err != nil {
		return RestorePoint{}, err
	}
	verifiedPoint, err := store.verifyDirectory(ctx, final, id)
	if err != nil {
		return RestorePoint{}, err
	}
	return store.describe(verifiedPoint, nil), nil
}

func (store *RestorePointStore) Inventory(ctx context.Context, currentVersion, recoveryVersion string, activeVersions []string) ([]RestorePoint, error) {
	if err := store.validate(); err != nil {
		return nil, err
	}
	protected := map[string][]string{}
	if currentVersion != "" {
		protected[currentVersion] = append(protected[currentVersion], "CURRENT")
	}
	if recoveryVersion != "" {
		protected[recoveryVersion] = append(protected[recoveryVersion], "RECOVERY")
	}
	for _, version := range activeVersions {
		if ValidateGatewayVersion(version) != nil {
			return nil, errors.New("active restore point protection version is invalid")
		}
		protected[version] = append(protected[version], "ACTIVE_TRANSACTION")
	}
	entries, err := os.ReadDir(store.Root)
	if errors.Is(err, os.ErrNotExist) {
		return []RestorePoint{}, nil
	}
	if err != nil {
		return nil, err
	}
	items := make([]RestorePoint, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !restorePointIDPattern.MatchString(entry.Name()) {
			if strings.HasPrefix(entry.Name(), ".point-") && strings.HasSuffix(entry.Name(), ".tmp") {
				continue
			}
			return nil, errors.New("restore point root contains an unmanaged entry")
		}
		manifest, err := store.verifyDirectory(ctx, filepath.Join(store.Root, entry.Name()), entry.Name())
		if err != nil {
			return nil, err
		}
		roles := append([]string(nil), protected[manifest.GatewayVersion]...)
		items = append(items, store.describe(manifest, roles))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Manifest.CreatedAt > items[j].Manifest.CreatedAt })
	return items, nil
}

// Get verifies one exact immutable point without trusting a caller-supplied
// path. Compatibility is evaluated against the currently installed signed
// host contract and must be enforced by the mutation caller.
func (store *RestorePointStore) Get(ctx context.Context, pointID string) (RestorePoint, error) {
	if err := store.validate(); err != nil {
		return RestorePoint{}, err
	}
	if ValidateRestorePointID(pointID) != nil {
		return RestorePoint{}, errors.New("restore point id is invalid")
	}
	manifest, err := store.verifyDirectory(ctx, filepath.Join(store.Root, pointID), pointID)
	if err != nil {
		return RestorePoint{}, err
	}
	return store.describe(manifest, nil), nil
}

func (store *RestorePointStore) Delete(ctx context.Context, pointID, currentVersion, recoveryVersion string, activeVersions []string) error {
	items, err := store.Inventory(ctx, currentVersion, recoveryVersion, activeVersions)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Manifest.PointID != pointID {
			continue
		}
		if item.Protected {
			return errors.New("current, recovery, or active-transaction restore point cannot be deleted")
		}
		return removeRestorePointDirectory(store.Root, filepath.Join(store.Root, pointID))
	}
	return errors.New("verified restore point was not found")
}

func (store *RestorePointStore) Prune(ctx context.Context, policy RestorePointPolicy, currentVersion, recoveryVersion string, activeVersions []string) ([]string, error) {
	if !validRestorePointPolicy(policy) {
		return nil, errors.New("restore point retention policy is invalid")
	}
	items, err := store.Inventory(ctx, currentVersion, recoveryVersion, activeVersions)
	if err != nil {
		return nil, err
	}
	eligible := make([]RestorePoint, 0, len(items))
	var total int64
	for _, item := range items {
		total += item.Manifest.TotalBytes
		if !item.Protected {
			eligible = append(eligible, item)
		}
	}
	// Inventory is newest-first. Never remove the configured minimum number of
	// historical points even when age/size bounds are exceeded.
	removed := []string{}
	now := store.now()
	for index := len(eligible) - 1; index >= policy.MinimumOldPoints; index-- {
		item := eligible[index]
		created, _ := time.Parse(time.RFC3339Nano, item.Manifest.CreatedAt)
		overCount := len(items)-len(removed) > policy.MaximumPoints
		overBytes := total > policy.MaximumBytes
		overAge := policy.MaximumAge > 0 && now.Sub(created) > policy.MaximumAge
		if !overCount && !overBytes && !overAge {
			continue
		}
		if err := removeRestorePointDirectory(store.Root, filepath.Join(store.Root, item.Manifest.PointID)); err != nil {
			return removed, err
		}
		removed = append(removed, item.Manifest.PointID)
		total -= item.Manifest.TotalBytes
	}
	return removed, nil
}

func (store *RestorePointStore) verifyDirectory(ctx context.Context, directory, expectedID string) (RestorePointManifest, error) {
	if err := ctx.Err(); err != nil {
		return RestorePointManifest{}, err
	}
	content, err := readBoundedRegular(filepath.Join(directory, "manifest.json"), 2<<20)
	if err != nil {
		return RestorePointManifest{}, errors.New("restore point manifest is unavailable")
	}
	digestContent, err := readBoundedRegular(filepath.Join(directory, "manifest.sha256"), 128)
	if err != nil {
		return RestorePointManifest{}, errors.New("restore point manifest checksum is unavailable")
	}
	digest := sha256.Sum256(content)
	if strings.TrimSpace(string(digestContent)) != hex.EncodeToString(digest[:]) {
		return RestorePointManifest{}, errors.New("restore point manifest checksum mismatch")
	}
	var manifest RestorePointManifest
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return RestorePointManifest{}, errors.New("restore point manifest JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !validRestorePointManifest(manifest) || manifest.PointID != expectedID {
		return RestorePointManifest{}, errors.New("restore point manifest contract is invalid")
	}
	verified, err := VerifyRelease(filepath.Join(store.ReleaseRoot, filepath.FromSlash(manifest.ReleaseTarget)), store.verificationFor(manifest.GatewayVersion, manifest.SchemaVersion))
	if err != nil || verified.Release.GatewayVersion != manifest.GatewayVersion || verified.Fingerprint != manifest.SignerKeySHA256 || verified.Release.HostContractSHA256 != manifest.HostContractSHA256 {
		return RestorePointManifest{}, errors.New("restore point signed release is unavailable or changed")
	}
	releaseSHA, _, err := hashFile(filepath.Join(store.ReleaseRoot, filepath.FromSlash(manifest.ReleaseTarget), ManifestFilename), MaximumManifestBytes)
	if err != nil || releaseSHA != manifest.ReleaseManifestSHA256 {
		return RestorePointManifest{}, errors.New("restore point release manifest changed")
	}
	var total int64
	expectedFiles := map[string]struct{}{"manifest.json": {}, "manifest.sha256": {}}
	for _, file := range manifest.Files {
		filename := filepath.Join(directory, filepath.FromSlash(file.Path))
		actual, size, err := hashFile(filename, MaximumFileBytes)
		if err != nil || size != file.Bytes || actual != file.SHA256 || total > maximumRestorePointBytes-size {
			return RestorePointManifest{}, errors.New("restore point file verification failed")
		}
		total += size
		expectedFiles[file.Path] = struct{}{}
	}
	if total != manifest.TotalBytes {
		return RestorePointManifest{}, errors.New("restore point total size mismatch")
	}
	if manifest.MihomoActiveGeneration != "" {
		marker, err := readBoundedRegular(filepath.Join(directory, "state", "mihomo", "state", "active-generation"), 256)
		if err != nil || strings.TrimSpace(string(marker)) != manifest.MihomoActiveGeneration {
			return RestorePointManifest{}, errors.New("restore point Mihomo active generation marker mismatch")
		}
	}
	if err := filepath.WalkDir(directory, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(filename)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("restore point contains an unsafe entry")
		}
		if info.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(directory, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, exists := expectedFiles[relative]; !exists {
			return errors.New("restore point contains an unmanifested file")
		}
		delete(expectedFiles, relative)
		return nil
	}); err != nil || len(expectedFiles) != 0 {
		return RestorePointManifest{}, errors.New("restore point file inventory is incomplete or unsafe")
	}
	if err := verifyLiveDatabase(ctx, filepath.Join(directory, "database", "state.db"), manifest.SchemaVersion); err != nil {
		return RestorePointManifest{}, errors.New("restore point database verification failed")
	}
	return manifest, nil
}

func (store *RestorePointStore) validate() error {
	if !filepath.IsAbs(store.Root) || !filepath.IsAbs(store.ReleaseRoot) || !filepath.IsAbs(store.StateDir) || !filepath.IsAbs(store.Configuration) || len(store.Verification.PublicKey) == 0 {
		return errors.New("complete fixed restore point store configuration is required")
	}
	if pathInside(store.StateDir, store.Root) || filepath.Clean(store.Root) == filepath.Clean(store.StateDir) {
		return errors.New("privileged restore points must remain outside unprivileged state")
	}
	return nil
}

func (store *RestorePointStore) now() time.Time {
	if store.Now != nil {
		return store.Now().UTC()
	}
	return time.Now().UTC()
}

func (store *RestorePointStore) verificationFor(version string, schema int64) VerificationPolicy {
	policy := store.Verification
	policy.InitialInstall = false
	policy.CurrentGatewayVersion = version
	policy.CurrentSchemaVersion = schema
	policy.AllowSameVersion = true
	// A historical release remains cryptographically verifiable after a host
	// lifecycle upgrade. Compatibility with the currently installed host
	// contract is reported separately and enforced before rollback.
	policy.CurrentHostContractSHA256 = ""
	return policy
}

func (store *RestorePointStore) describe(manifest RestorePointManifest, roles []string) RestorePoint {
	reason := "HOST_CONTRACT_UNKNOWN"
	compatible := false
	if digestPattern.MatchString(store.Verification.CurrentHostContractSHA256) {
		compatible = manifest.HostContractSHA256 == store.Verification.CurrentHostContractSHA256
		if compatible {
			reason = "COMPATIBLE"
		} else {
			reason = "HOST_CONTRACT_CHANGED"
		}
	}
	roles = append([]string(nil), roles...)
	return RestorePoint{Manifest: manifest, Protected: len(roles) > 0, Roles: roles, Compatible: compatible, CompatibilityReason: reason}
}

func validRestorePointManifest(manifest RestorePointManifest) bool {
	created, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt)
	if manifest.FormatVersion != RestorePointFormatVersion || !restorePointIDPattern.MatchString(manifest.PointID) || manifest.Kind != RestorePointKindPreUpdate || err != nil || created.IsZero() || ValidateGatewayVersion(manifest.GatewayVersion) != nil || manifest.SchemaVersion < 1 || manifest.ReleaseTarget != "releases/v"+manifest.GatewayVersion || !digestPattern.MatchString(manifest.ReleaseManifestSHA256) || !digestPattern.MatchString(manifest.SignerKeySHA256) || !digestPattern.MatchString(manifest.HostContractSHA256) || manifest.Verification != "PASS" || len(manifest.Files) < 2 || len(manifest.Files) > maximumRestorePointFiles || manifest.TotalBytes <= 0 || manifest.TotalBytes > maximumRestorePointBytes {
		return false
	}
	previous := ""
	var total int64
	hasDatabase := false
	hasConfiguration := false
	hasMihomoActiveConfig := manifest.MihomoActiveGeneration == ""
	hasMihomoActiveMarker := manifest.MihomoActiveGeneration == ""
	if manifest.MihomoActiveGeneration != "" && !validMihomoGenerationID(manifest.MihomoActiveGeneration) {
		return false
	}
	for _, file := range manifest.Files {
		if !safeRelativePath(file.Path) || previous >= file.Path || file.Bytes <= 0 || file.Bytes > MaximumFileBytes || !digestPattern.MatchString(file.SHA256) || total > maximumRestorePointBytes-file.Bytes {
			return false
		}
		previous = file.Path
		total += file.Bytes
		hasDatabase = hasDatabase || file.Path == "database/state.db"
		hasConfiguration = hasConfiguration || file.Path == "config/config.yaml"
		hasMihomoActiveConfig = hasMihomoActiveConfig || file.Path == "state/mihomo/generations/"+manifest.MihomoActiveGeneration+"/config.yaml"
		hasMihomoActiveMarker = hasMihomoActiveMarker || file.Path == "state/mihomo/state/active-generation"
	}
	return total == manifest.TotalBytes && hasDatabase && hasConfiguration && hasMihomoActiveConfig && hasMihomoActiveMarker
}

// inspectMihomoActiveGeneration captures the exact data-plane generation that
// systemd would start after the restore. The symlink itself is not copied into
// an immutable point; only its validated generation identity is stored and the
// fixed restore helper reconstructs the relative link after restoring the
// generation tree.
func inspectMihomoActiveGeneration(stateDirectory string) (string, error) {
	root := filepath.Join(filepath.Clean(stateDirectory), "mihomo")
	active := filepath.Join(root, "active")
	info, err := os.Lstat(active)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("Mihomo active path is not a safe symlink")
	}
	target, err := os.Readlink(active)
	if err != nil || filepath.IsAbs(target) {
		return "", errors.New("Mihomo active link target is unavailable or absolute")
	}
	clean := filepath.Clean(target)
	generation := filepath.Base(clean)
	if filepath.Dir(clean) != "generations" || clean != filepath.Join("generations", generation) || !validMihomoGenerationID(generation) {
		return "", errors.New("Mihomo active link escapes its generation root")
	}
	generationRoot := filepath.Join(root, "generations", generation)
	generationInfo, err := os.Lstat(generationRoot)
	if err != nil || generationInfo.Mode()&os.ModeSymlink != 0 || !generationInfo.IsDir() {
		return "", errors.New("Mihomo active generation directory is unavailable or unsafe")
	}
	configInfo, err := os.Lstat(filepath.Join(generationRoot, "config.yaml"))
	if err != nil || configInfo.Mode()&os.ModeSymlink != 0 || !configInfo.Mode().IsRegular() || configInfo.Size() <= 0 {
		return "", errors.New("Mihomo active generation configuration is unavailable or unsafe")
	}
	marker, err := readBoundedRegular(filepath.Join(root, "state", "active-generation"), 256)
	if err != nil || strings.TrimSpace(string(marker)) != generation {
		return "", errors.New("Mihomo active link and durable marker do not match")
	}
	return generation, nil
}

func validMihomoGenerationID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func validRestorePointPolicy(policy RestorePointPolicy) bool {
	return policy.MaximumPoints >= 2 && policy.MaximumPoints <= 32 && policy.MaximumBytes >= 256<<20 && policy.MaximumBytes <= 128<<30 && policy.MaximumAge >= 0 && policy.MaximumAge <= 10*365*24*time.Hour && policy.MinimumOldPoints >= 0 && policy.MinimumOldPoints <= policy.MaximumPoints-1
}

func copyRestorePointTree(ctx context.Context, sourceRoot, targetRoot string, add func(string, string) error) error {
	info, err := os.Lstat(sourceRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("restore point source tree is unsafe")
	}
	return filepath.WalkDir(sourceRoot, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(filename)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("restore point source contains a symlink or unreadable entry")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("restore point source contains a non-regular entry")
		}
		relative, err := filepath.Rel(sourceRoot, filename)
		if err != nil {
			return err
		}
		return add(filename, filepath.ToSlash(filepath.Join(targetRoot, relative)))
	})
}

func newRestorePointID(now time.Time) (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("generate restore point id failed")
	}
	return "point-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func removeRestorePointTemporary(root, temporary string) error {
	if filepath.Dir(filepath.Clean(temporary)) != filepath.Clean(root) || !strings.HasPrefix(filepath.Base(temporary), ".point-") || !strings.HasSuffix(filepath.Base(temporary), ".tmp") {
		return errors.New("refuse unsafe restore point temporary cleanup")
	}
	return removeVerifiedRegularTree(temporary, maximumRestorePointFiles+8)
}

func removeRestorePointDirectory(root, directory string) error {
	if filepath.Dir(filepath.Clean(directory)) != filepath.Clean(root) || !restorePointIDPattern.MatchString(filepath.Base(directory)) {
		return errors.New("refuse unsafe restore point deletion")
	}
	if err := removeVerifiedRegularTree(directory, maximumRestorePointFiles+8); err != nil {
		return err
	}
	return syncDirectoryPath(root)
}

func removeVerifiedRegularTree(root string, maximum int) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("refuse unsafe restore point tree removal")
	}
	paths := make([]string, 0, 128)
	if err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(filename)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() || len(paths) >= maximum {
			return errors.New("restore point tree contains an unsafe or excessive entry")
		}
		paths = append(paths, filename)
		return nil
	}); err != nil {
		return err
	}
	for index := len(paths) - 1; index >= 0; index-- {
		if err := os.Remove(paths[index]); err != nil {
			return err
		}
	}
	return nil
}
