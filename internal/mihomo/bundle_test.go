package mihomo

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteCandidatePublishesCompleteBundle(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "generation-1")
	bundle := Bundle{
		Main: []byte("secret: test\n"),
		Providers: map[string][]byte{
			"providers/a.yaml": []byte("proxies: []\n"),
		},
	}
	if err := WriteCandidate(destination, bundle); err != nil {
		t.Fatalf("WriteCandidate() error = %v", err)
	}
	for _, relative := range []string{"config.yaml", "providers/a.yaml"} {
		filename := filepath.Join(destination, filepath.FromSlash(relative))
		content, err := os.ReadFile(filename)
		if err != nil || len(content) == 0 {
			t.Fatalf("read %s: content=%q error=%v", relative, content, err)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filename)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o640 {
				t.Fatalf("provider-readable immutable mode for %s = %v", relative, info.Mode().Perm())
			}
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 {
			t.Fatalf("generation directory mode = %v", info.Mode().Perm())
		}
	}
	if err := WriteCandidate(destination, bundle); err == nil {
		t.Fatal("WriteCandidate(existing) error = nil")
	}
}

func TestWriteCandidateRejectsProviderTraversal(t *testing.T) {
	bundle := Bundle{Main: []byte("main"), Providers: map[string][]byte{"../outside.yaml": []byte("bad")}}
	if err := WriteCandidate(filepath.Join(t.TempDir(), "generation"), bundle); err == nil {
		t.Fatal("WriteCandidate(traversal) error = nil")
	}
}
