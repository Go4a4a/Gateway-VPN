package hostboot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAcceptsCanonicalUUIDAndRejectsUnsafeSources(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "boot_id")
	if err := os.WriteFile(path, []byte("A7C2D386-381E-4B36-8E2B-0A766EB57E03\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	value, err := Read(path)
	if err != nil || value != "a7c2d386-381e-4b36-8e2b-0a766eb57e03" {
		t.Fatalf("Read() = %q, %v", value, err)
	}
	if err := os.WriteFile(path, []byte("boot-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("non-UUID boot identity accepted")
	}
	link := filepath.Join(root, "boot-link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := Read(link); err == nil {
			t.Fatal("symlink boot identity accepted")
		}
	}
	if _, err := Read("relative/boot_id"); err == nil {
		t.Fatal("relative boot identity path accepted")
	}
}
