//go:build linux

package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRestorePointRollbackRestoresExactMihomoActiveGenerationAndModes(t *testing.T) {
	fixture := newEngineFixture(t)
	writeMihomoActiveFixture(t, fixture.stateDir, "historical-generation", "historical")
	targetPoint := prepareManualRollbackFixture(t, fixture)
	writeMihomoActiveFixture(t, fixture.stateDir, "newer-generation", "newer")

	if _, err := fixture.engine.RollbackToRestorePoint(context.Background(), targetPoint); err != nil {
		t.Fatal(err)
	}
	assertMihomoActiveFixture(t, fixture.stateDir, "historical-generation", "historical")
}

func TestRestorePointRollbackFailureRestoresSafetyMihomoGeneration(t *testing.T) {
	fixture := newEngineFixture(t)
	writeMihomoActiveFixture(t, fixture.stateDir, "historical-generation", "historical")
	targetPoint := prepareManualRollbackFixture(t, fixture)
	writeMihomoActiveFixture(t, fixture.stateDir, "newer-generation", "newer")
	fixture.runtime.failVersion = "1.1.0"

	if _, err := fixture.engine.RollbackToRestorePoint(context.Background(), targetPoint); err == nil {
		t.Fatal("unhealthy historical Mihomo generation unexpectedly remained active")
	}
	assertMihomoActiveFixture(t, fixture.stateDir, "newer-generation", "newer")
}

func TestRestorePointRejectsMismatchedMihomoActiveMarker(t *testing.T) {
	store, databasePath, _ := restorePointFixture(t)
	writeMihomoActiveFixture(t, store.StateDir, "generation-a", "a")
	if err := os.WriteFile(filepath.Join(store.StateDir, "mihomo", "state", "active-generation"), []byte("generation-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreatePreUpdate(context.Background(), "1.2.0", 34, databasePath); err == nil {
		t.Fatal("mismatched Mihomo link and durable marker were accepted")
	}
}

func TestRestoreProjectionPreservesRootOnlySecretsAndStateRootMode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact restore ownership contract requires root")
	}
	fixture := newEngineFixture(t)
	for _, relative := range []string{"secrets/management/root-only.key", "secrets/wireguard-ingress/root-only.key"} {
		filename := filepath.Join(fixture.stateDir, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte("root-only"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	targetPoint := prepareManualRollbackFixture(t, fixture)
	fixture.engine.StateUID = 12345
	fixture.engine.StateGID = 12346
	if err := os.Chmod(fixture.stateDir, 0o710); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engine.RollbackToRestorePoint(context.Background(), targetPoint); err != nil {
		t.Fatal(err)
	}
	// Opening the live SQLite database preserves the production state root's
	// traverse-only service-group access. Secrets below it remain independently
	// protected by their exact ownership and 0600/0700 modes.
	if mode := mustRestoreStat(t, fixture.stateDir).Mode().Perm(); mode != 0o710 {
		t.Fatalf("state root mode = %o, want 710", mode)
	}
	for _, relative := range []string{"secrets/management/root-only.key", "secrets/wireguard-ingress/root-only.key"} {
		info := mustRestoreStat(t, filepath.Join(fixture.stateDir, filepath.FromSlash(relative)))
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("root-only restore %q = uid:%d gid:%d mode:%o", relative, stat.Uid, stat.Gid, info.Mode().Perm())
		}
	}
	ordinary := mustRestoreStat(t, filepath.Join(fixture.stateDir, "secrets", "mihomo-api-secret"))
	stat := ordinary.Sys().(*syscall.Stat_t)
	if stat.Uid != 12345 || stat.Gid != 12346 || ordinary.Mode().Perm() != 0o600 {
		t.Fatalf("ordinary secret restore = uid:%d gid:%d mode:%o", stat.Uid, stat.Gid, ordinary.Mode().Perm())
	}
}

func TestRestoreProjectionPreparationFailureCleansEveryCandidate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact restore mode contract requires root")
	}
	fixture := newEngineFixture(t)
	targetPoint := prepareManualRollbackFixture(t, fixture)
	mihomoRoot := filepath.Join(fixture.stateDir, "mihomo")
	if err := os.MkdirAll(mihomoRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mihomoRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engine.RollbackToRestorePoint(context.Background(), targetPoint); err == nil {
		t.Fatal("unsafe restore parent mode was accepted")
	}
	for _, parent := range []string{fixture.stateDir, filepath.Dir(fixture.configPath), mihomoRoot} {
		matches, err := filepath.Glob(filepath.Join(parent, "*.restore-candidate"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("partial restore candidates below %q = %v, %v", parent, matches, err)
		}
	}
}

func mustRestoreStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("unsafe restore path %q: %v", path, err)
	}
	return info
}

func writeMihomoActiveFixture(t *testing.T, stateDirectory, generation, value string) {
	t.Helper()
	root := filepath.Join(stateDirectory, "mihomo")
	generationRoot := filepath.Join(root, "generations", generation)
	providerRoot := filepath.Join(generationRoot, "providers")
	stateRoot := filepath.Join(root, "state")
	for _, directory := range []string{root, filepath.Join(root, "generations"), generationRoot, providerRoot} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		filepath.Join(generationRoot, "config.yaml"):  "mode: " + value + "\n",
		filepath.Join(providerRoot, "provider.yaml"):  "proxies: [] # " + value + "\n",
		filepath.Join(stateRoot, "active-generation"): generation + "\n",
		filepath.Join(stateRoot, "lkg-generation"):    generation + "\n",
	} {
		mode := os.FileMode(0o640)
		if filepath.Dir(name) == stateRoot {
			mode = 0o600
		}
		if err := os.WriteFile(name, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
	}
	active := filepath.Join(root, "active")
	if info, err := os.Lstat(active); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("fixture active path is not a symlink: %v", info.Mode())
		}
		if err := os.Remove(active); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("generations", generation), active); err != nil {
		t.Fatal(err)
	}
}

func assertMihomoActiveFixture(t *testing.T, stateDirectory, generation, value string) {
	t.Helper()
	root := filepath.Join(stateDirectory, "mihomo")
	target, err := os.Readlink(filepath.Join(root, "active"))
	if err != nil || target != filepath.Join("generations", generation) {
		t.Fatalf("Mihomo active link = %q,%v", target, err)
	}
	for _, directory := range []string{
		filepath.Join(root, "generations"),
		filepath.Join(root, "generations", generation),
		filepath.Join(root, "generations", generation, "providers"),
	} {
		if mode := mustRestoreStat(t, directory).Mode().Perm(); mode != 0o750 {
			t.Fatalf("Mihomo directory %q mode = %o, want 750", directory, mode)
		}
	}
	for _, filename := range []string{
		filepath.Join(root, "generations", generation, "config.yaml"),
		filepath.Join(root, "generations", generation, "providers", "provider.yaml"),
	} {
		info := mustRestoreStat(t, filename)
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("Mihomo file %q mode = %o, want 640", filename, info.Mode().Perm())
		}
	}
	content, err := os.ReadFile(filepath.Join(root, "generations", generation, "config.yaml"))
	if err != nil || string(content) != "mode: "+value+"\n" {
		t.Fatalf("Mihomo active config = %q,%v", content, err)
	}
}
