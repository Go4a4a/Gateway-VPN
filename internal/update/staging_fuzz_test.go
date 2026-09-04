package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzExtractReleaseArchive(f *testing.F) {
	f.Add(seedFuzzReleaseArchive())
	f.Add([]byte("not a gzip archive"))
	f.Add([]byte{0x1f, 0x8b, 0x08})
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 4<<20 {
			return
		}
		destination := t.TempDir()
		written, files, err := ExtractReleaseArchive(context.Background(), bytes.NewReader(content), destination)
		if err != nil {
			return
		}
		if files < 7 || files > MaximumFiles+2 || written <= 0 || written > MaximumArtifactBytes {
			t.Fatalf("successful extraction returned invalid bounds: bytes=%d files=%d", written, files)
		}
		var observedBytes int64
		observedFiles := 0
		walkErr := filepath.WalkDir(destination, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				t.Fatalf("successful extraction created symlink %q", name)
			}
			relative, relErr := filepath.Rel(destination, name)
			if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				t.Fatalf("successful extraction escaped destination: %q", name)
			}
			if entry.Type().IsRegular() {
				info, infoErr := entry.Info()
				if infoErr != nil {
					return infoErr
				}
				observedFiles++
				observedBytes += info.Size()
			}
			return nil
		})
		if walkErr != nil || observedFiles != files || observedBytes != written {
			t.Fatalf("successful extraction accounting mismatch: bytes=%d/%d files=%d/%d error=%v", observedBytes, written, observedFiles, files, walkErr)
		}
	})
}

func seedFuzzReleaseArchive() []byte {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	for index, name := range []string{"release.json", "manifest.json", "manifest.sha256", "release.sig", "bin/gateway-vpn", "libexec/mihomo", "config/default.yaml"} {
		content := []byte{byte('a' + index)}
		_ = tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
		_, _ = tarWriter.Write(content)
	}
	_ = tarWriter.Close()
	_ = gzipWriter.Close()
	return compressed.Bytes()
}
