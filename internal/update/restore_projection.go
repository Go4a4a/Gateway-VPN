package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type restoreTreeProjection struct {
	SourcePrefix string
	LivePath     string
	Candidate    string
}

type restoreProjection struct {
	Point             RestorePoint
	Root              string
	Database          string
	DatabaseSHA256    string
	DatabaseBytes     int64
	Configuration     string
	Trees             []restoreTreeProjection
	transactionID     string
	databaseLive      string
	configurationLive string
}

var restoreStateTrees = []struct {
	prefix string
	live   string
}{
	{prefix: "state/secrets", live: "secrets"},
	{prefix: "state/subscriptions", live: "subscriptions"},
	{prefix: "state/tls", live: "tls"},
	{prefix: "state/mihomo/generations", live: "mihomo/generations"},
	{prefix: "state/mihomo/state", live: "mihomo/state"},
}

func (engine *Engine) prepareRestoreProjection(ctx context.Context, pointID, transactionID string) (restoreProjection, error) {
	if ValidateRestorePointID(pointID) != nil || !updateIDPattern.MatchString(transactionID) {
		return restoreProjection{}, errors.New("restore projection identity is invalid")
	}
	point, err := engine.RestorePoints.Get(ctx, pointID)
	if err != nil {
		return restoreProjection{}, err
	}
	if !point.Compatible {
		return restoreProjection{}, errors.New("restore point host contract is incompatible")
	}
	if _, err := safeRoot(engine.StateDir); err != nil {
		return restoreProjection{}, errors.New("restore state root is unsafe")
	}
	if _, err := safeRoot(filepath.Dir(engine.ConfigPath)); err != nil {
		return restoreProjection{}, errors.New("restore configuration parent is unsafe")
	}
	root := filepath.Join(engine.RestorePoints.Root, pointID)
	projection := restoreProjection{
		Point: point, Root: root, transactionID: transactionID,
		databaseLive: engine.DatabasePath, configurationLive: engine.ConfigPath,
		Database:      restoreCandidateFile(engine.DatabasePath, transactionID),
		Configuration: restoreCandidateFile(engine.ConfigPath, transactionID),
	}
	prepared := false
	defer func() {
		if !prepared {
			_ = projection.cleanupCandidates()
		}
	}()
	for _, file := range point.Manifest.Files {
		if file.Path == "database/state.db" {
			projection.DatabaseSHA256, projection.DatabaseBytes = file.SHA256, file.Bytes
			break
		}
	}
	if err := removeRestoreCandidateFile(projection.Database); err != nil {
		return restoreProjection{}, err
	}
	if err := removeRestoreCandidateFile(projection.Configuration); err != nil {
		return restoreProjection{}, err
	}
	if err := copyExclusiveFile(filepath.Join(root, "database", "state.db"), projection.Database, 0o600, MaximumFileBytes); err != nil {
		return restoreProjection{}, fmt.Errorf("prepare restore database: %w", err)
	}
	if err := engine.applyOwnership(projection.Database); err != nil {
		return restoreProjection{}, err
	}
	if err := copyExclusiveFile(filepath.Join(root, "config", "config.yaml"), projection.Configuration, 0o640, MaximumFileBytes); err != nil {
		return restoreProjection{}, fmt.Errorf("prepare restore configuration: %w", err)
	}
	if err := setFileOwnership(projection.Configuration, engine.rootOwnerUID, engine.StateGID); err != nil {
		return restoreProjection{}, err
	}
	for _, item := range restoreStateTrees {
		live := filepath.Join(engine.StateDir, filepath.FromSlash(item.live))
		candidate := restoreCandidateTree(live, transactionID)
		if err := removeVerifiedRegularTree(candidate, maximumRestorePointFiles+8); err != nil {
			return restoreProjection{}, err
		}
		tree := restoreTreeProjection{SourcePrefix: item.prefix, LivePath: live, Candidate: candidate}
		// Register the candidate before its first filesystem mutation so the
		// outer preparation guard can remove a partially copied/chowned tree.
		projection.Trees = append(projection.Trees, tree)
		files := restoreFilesBelow(point.Manifest.Files, item.prefix)
		if err := engine.ensureRestoreTreeParent(filepath.Dir(candidate), restoreTreeParentMode(item.prefix)); err != nil {
			return restoreProjection{}, err
		}
		if err := os.Mkdir(candidate, restoreTreeRootMode(item.prefix)); err != nil {
			return restoreProjection{}, err
		}
		if len(files) > 0 {
			if err := engine.copyRestoreFiles(ctx, root, candidate, item.prefix, files); err != nil {
				return restoreProjection{}, err
			}
		}
		if err := engine.applyRestoreTreeSecurity(candidate, item.prefix); err != nil {
			return restoreProjection{}, err
		}
	}
	if err := engine.verifyRestoreProjection(ctx, projection); err != nil {
		return restoreProjection{}, err
	}
	prepared = true
	return projection, nil
}

func (engine *Engine) copyRestoreFiles(ctx context.Context, pointRoot, candidateRoot, prefix string, files []RestorePointFile) error {
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative := strings.TrimPrefix(file.Path, prefix+"/")
		if !safeRelativePath(relative) {
			return errors.New("restore state relative path is invalid")
		}
		target := filepath.Join(candidateRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := copyExclusiveFile(filepath.Join(pointRoot, filepath.FromSlash(file.Path)), target, 0o600, MaximumFileBytes); err != nil {
			return err
		}
	}
	return syncTree(candidateRoot)
}

// applyRestoreTreeSecurity reconstructs the fixed ownership boundary rather
// than inheriting ownership from the privileged rollback helper. Management
// Fabric and WireGuard ingress identities must remain root-only even though
// they live below the otherwise unprivileged Gateway state tree.
func (engine *Engine) applyRestoreTreeSecurity(root, sourcePrefix string) error {
	if !filepath.IsAbs(root) || restoreTreeRootMode(sourcePrefix) == 0 {
		return errors.New("restore tree security scope is invalid")
	}
	if sourcePrefix == "state/secrets" {
		for _, relative := range []string{"subscriptions", "management", "wireguard-ingress"} {
			if err := os.MkdirAll(filepath.Join(root, relative), 0o700); err != nil {
				return err
			}
		}
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("restore candidate tree is unsafe")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("restore candidate tree path is invalid")
		}
		relative = filepath.ToSlash(relative)
		uid, gid := engine.StateUID, engine.StateGID
		if sourcePrefix == "state/secrets" && restoreRootSecret(relative) {
			uid, gid = engine.rootOwnerUID, engine.rootOwnerGID
		}
		mode := os.FileMode(0o600)
		if info.IsDir() {
			mode = 0o700
			if sourcePrefix == "state/mihomo/generations" || relative == "." {
				mode = restoreTreeRootMode(sourcePrefix)
			}
		} else if sourcePrefix == "state/mihomo/generations" {
			mode = 0o640
		} else if sourcePrefix == "state/tls" && relative == "cert.pem" {
			mode = 0o644
		}
		// The fixed systemd helper deliberately has CAP_CHOWN but not the much
		// broader CAP_FOWNER. Set the final mode while root still owns the
		// freshly copied candidate, then transfer its bounded ownership class.
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		return setFileOwnership(path, uid, gid)
	})
}

func restoreRootSecret(relative string) bool {
	return relative == "management" || strings.HasPrefix(relative, "management/") ||
		relative == "wireguard-ingress" || strings.HasPrefix(relative, "wireguard-ingress/")
}

func restoreTreeRootMode(sourcePrefix string) os.FileMode {
	switch sourcePrefix {
	case "state/secrets", "state/subscriptions", "state/tls", "state/mihomo/state":
		return 0o700
	case "state/mihomo/generations":
		return 0o750
	default:
		return 0
	}
}

func restoreTreeParentMode(sourcePrefix string) os.FileMode {
	if strings.HasPrefix(sourcePrefix, "state/mihomo/") {
		return 0o750
	}
	return 0o700
}

func (engine *Engine) ensureRestoreTreeParent(parent string, mode os.FileMode) error {
	info, err := os.Lstat(parent)
	if errors.Is(err, os.ErrNotExist) {
		grandparent := filepath.Dir(parent)
		if _, err := safeRoot(grandparent); err != nil {
			return errors.New("restore tree parent ancestor is unsafe")
		}
		if err := os.Mkdir(parent, mode); err != nil {
			return err
		}
		if err := setFileOwnership(parent, engine.StateUID, engine.StateGID); err != nil {
			return err
		}
		if err := syncDirectoryPath(grandparent); err != nil {
			return err
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("restore tree parent is unsafe")
	}
	actual := info.Mode().Perm()
	if filepath.Clean(parent) == filepath.Clean(engine.StateDir) {
		if !validRestoreStateRootMode(actual) {
			return errors.New("restore state root mode is unsafe")
		}
		return nil
	}
	if !validRestoreTreeParentMode(actual, mode) {
		return errors.New("restore tree parent mode is unsafe")
	}
	return nil
}

func (engine *Engine) verifyRestoreProjection(ctx context.Context, projection restoreProjection) error {
	if err := verifyLiveDatabase(ctx, projection.Database, projection.Point.Manifest.SchemaVersion); err != nil {
		return errors.New("restore projection database verification failed")
	}
	for _, file := range projection.Point.Manifest.Files {
		candidate := ""
		switch file.Path {
		case "database/state.db":
			candidate = projection.Database
		case "config/config.yaml":
			candidate = projection.Configuration
		default:
			for _, tree := range projection.Trees {
				if tree.Candidate != "" && strings.HasPrefix(file.Path, tree.SourcePrefix+"/") {
					relative := strings.TrimPrefix(file.Path, tree.SourcePrefix+"/")
					candidate = filepath.Join(tree.Candidate, filepath.FromSlash(relative))
					break
				}
			}
		}
		if candidate == "" {
			return errors.New("restore projection does not cover its manifest")
		}
		digest, size, err := hashFile(candidate, MaximumFileBytes)
		expectedDigest, expectedSize := file.SHA256, file.Bytes
		if file.Path == "database/state.db" {
			expectedDigest, expectedSize = projection.DatabaseSHA256, projection.DatabaseBytes
		}
		if err != nil || digest != expectedDigest || size != expectedSize {
			return errors.New("restore projection file verification failed")
		}
	}
	if generation := projection.Point.Manifest.MihomoActiveGeneration; generation != "" {
		var generationRoot string
		for _, tree := range projection.Trees {
			if tree.SourcePrefix == "state/mihomo/generations" {
				generationRoot = filepath.Join(tree.Candidate, generation)
				break
			}
		}
		info, err := os.Lstat(generationRoot)
		configInfo, configErr := os.Lstat(filepath.Join(generationRoot, "config.yaml"))
		if generationRoot == "" || err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || configErr != nil || configInfo.Mode()&os.ModeSymlink != 0 || !configInfo.Mode().IsRegular() {
			return errors.New("restore projection Mihomo active generation is unavailable or unsafe")
		}
	}
	return nil
}

func (engine *Engine) applyRestoreProjection(ctx context.Context, projection restoreProjection) error {
	if err := engine.verifyRestoreProjection(ctx, projection); err != nil {
		return err
	}
	for _, tree := range projection.Trees {
		if err := replaceRestoreTree(tree.Candidate, tree.LivePath, projection.transactionID); err != nil {
			return err
		}
	}
	if err := restoreMihomoActiveLink(engine.StateDir, projection.Point.Manifest.MihomoActiveGeneration, projection.transactionID); err != nil {
		return err
	}
	if err := replaceFile(projection.Configuration, projection.configurationLive); err != nil {
		return errors.New("restore configuration atomic replacement failed")
	}
	if err := setFileOwnership(projection.configurationLive, engine.rootOwnerUID, engine.StateGID); err != nil {
		return err
	}
	if err := os.Chmod(projection.configurationLive, 0o640); err != nil {
		return err
	}
	if err := syncDirectoryPath(filepath.Dir(projection.configurationLive)); err != nil {
		return err
	}
	if err := removeDatabaseSidecars(projection.databaseLive); err != nil {
		return err
	}
	if err := replaceFile(projection.Database, projection.databaseLive); err != nil {
		return errors.New("restore database atomic replacement failed")
	}
	if err := engine.applyOwnership(projection.databaseLive); err != nil {
		return err
	}
	if err := syncDirectoryPath(filepath.Dir(projection.databaseLive)); err != nil {
		return err
	}
	return verifyLiveDatabase(ctx, projection.databaseLive, projection.Point.Manifest.SchemaVersion)
}

func restoreMihomoActiveLink(stateDirectory, generation, transactionID string) error {
	if !filepath.IsAbs(stateDirectory) || !updateIDPattern.MatchString(transactionID) || generation != "" && !validMihomoGenerationID(generation) {
		return errors.New("restore Mihomo active link identity is invalid")
	}
	root := filepath.Join(filepath.Clean(stateDirectory), "mihomo")
	if _, err := safeRoot(root); err != nil {
		return errors.New("restore Mihomo root is unsafe")
	}
	active := filepath.Join(root, "active")
	if info, err := os.Lstat(active); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("restore Mihomo active path is not a symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if generation == "" {
		if err := os.Remove(active); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectoryPath(root)
	}
	generationRoot := filepath.Join(root, "generations", generation)
	info, err := os.Lstat(generationRoot)
	configInfo, configErr := os.Lstat(filepath.Join(generationRoot, "config.yaml"))
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || configErr != nil || configInfo.Mode()&os.ModeSymlink != 0 || !configInfo.Mode().IsRegular() {
		return errors.New("restore Mihomo active generation is unavailable or unsafe")
	}
	temporary := filepath.Join(root, ".active-"+transactionID+".restore-candidate")
	if temporaryInfo, err := os.Lstat(temporary); err == nil {
		if temporaryInfo.Mode()&os.ModeSymlink == 0 {
			return errors.New("restore Mihomo temporary active link is unsafe")
		}
		if err := os.Remove(temporary); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Symlink(filepath.Join("generations", generation), temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, active); err != nil {
		return err
	}
	return syncDirectoryPath(root)
}

func (projection restoreProjection) cleanupCandidates() error {
	var result error
	result = errors.Join(result, removeRestoreCandidateFile(projection.Database), removeRestoreCandidateFile(projection.Configuration))
	for _, tree := range projection.Trees {
		candidate := tree.Candidate
		if candidate == "" {
			candidate = restoreCandidateTree(tree.LivePath, projection.transactionID)
		}
		result = errors.Join(result, removeVerifiedRegularTree(candidate, maximumRestorePointFiles+8))
	}
	return result
}

func replaceRestoreTree(candidate, live, transactionID string) error {
	if !filepath.IsAbs(live) || !updateIDPattern.MatchString(transactionID) {
		return errors.New("restore tree target is invalid")
	}
	parent := filepath.Dir(filepath.Clean(live))
	if _, err := safeRoot(parent); err != nil {
		if candidate == "" && errors.Is(pathError(parent), os.ErrNotExist) {
			return nil
		}
		return errors.New("restore tree parent is unsafe")
	}
	previous := filepath.Join(parent, "."+filepath.Base(live)+"."+transactionID+".restore-previous")
	if candidate != "" {
		if filepath.Dir(filepath.Clean(candidate)) != parent || filepath.Clean(candidate) != restoreCandidateTree(live, transactionID) {
			return errors.New("restore tree candidate is invalid")
		}
		info, err := os.Lstat(candidate)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("restore tree candidate is unavailable")
		}
	}
	liveExists, err := realDirectoryExists(live)
	if err != nil {
		return err
	}
	previousExists, err := realDirectoryExists(previous)
	if err != nil {
		return err
	}
	if liveExists && previousExists {
		if err := removeVerifiedRegularTree(previous, maximumRestorePointFiles+8); err != nil {
			return err
		}
		previousExists = false
	}
	if liveExists {
		if err := os.Rename(live, previous); err != nil {
			return err
		}
		previousExists = true
		if err := syncDirectoryPath(parent); err != nil {
			return err
		}
	}
	if candidate != "" {
		if err := os.Rename(candidate, live); err != nil {
			return err
		}
		if err := syncDirectoryPath(parent); err != nil {
			return err
		}
	}
	if previousExists {
		if err := removeVerifiedRegularTree(previous, maximumRestorePointFiles+8); err != nil {
			return err
		}
		return syncDirectoryPath(parent)
	}
	return nil
}

func pathError(path string) error {
	_, err := os.Lstat(path)
	return err
}

func restoreFilesBelow(files []RestorePointFile, prefix string) []RestorePointFile {
	result := make([]RestorePointFile, 0)
	for _, file := range files {
		if strings.HasPrefix(file.Path, prefix+"/") {
			result = append(result, file)
		}
	}
	return result
}

func restoreCandidateFile(live, transactionID string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(live)), "."+filepath.Base(live)+"."+transactionID+".restore-candidate")
}

func restoreCandidateTree(live, transactionID string) string {
	return restoreCandidateFile(live, transactionID)
}

func removeRestoreCandidateFile(filename string) error {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("restore candidate file is unsafe")
	}
	return os.Remove(filename)
}

func realDirectoryExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("restore managed tree is unsafe")
	}
	return true, nil
}
