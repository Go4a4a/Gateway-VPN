//go:build linux

package mihomoruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicSymlinkSwitcherPublishesAndReplacesOnlyGenerationLinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	for _, generation := range []string{"generation-1", "generation-2"} {
		directory := filepath.Join(root, "generations", generation)
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "config.yaml"), []byte("proxies: []\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	switcher := AtomicSymlinkSwitcher{}
	for _, generation := range []string{"generation-1", "generation-2"} {
		if err := switcher.Activate(root, generation, filepath.Join(root, "generations", generation)); err != nil {
			t.Fatalf("Activate(%s) error = %v", generation, err)
		}
		current, err := switcher.Current(root)
		if err != nil || current != generation {
			t.Fatalf("Current() = %s, %v", current, err)
		}
		info, err := os.Lstat(filepath.Join(root, "active"))
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("active path is not a symlink: %v, %v", info, err)
		}
	}
	if err := switcher.Remove(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "active")); !os.IsNotExist(err) {
		t.Fatalf("active link remains after Remove: %v", err)
	}
}

func TestAtomicSymlinkSwitcherRejectsNonLinkActivePathAndDirectoryEscape(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	directory := filepath.Join(root, "generations", "generation-1")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.yaml"), []byte("proxies: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "active"), 0o700); err != nil {
		t.Fatal(err)
	}
	switcher := AtomicSymlinkSwitcher{}
	if err := switcher.Activate(root, "generation-1", directory); err == nil {
		t.Fatal("Activate(non-link active path) error = nil")
	}
	if err := switcher.Activate(root, "generation-1", filepath.Join(root, "..", "generation-1")); err == nil {
		t.Fatal("Activate(directory escape) error = nil")
	}
}
