package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDatabaseFixtureGenerationIsByteReproducible(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	first := t.TempDir()
	second := t.TempDir()
	if err := generateDatabases(first, repository); err != nil {
		t.Fatal(err)
	}
	if err := generateDatabases(second, repository); err != nil {
		t.Fatal(err)
	}
	firstTree := readFixtureTree(t, filepath.Join(first, "database"))
	secondTree := readFixtureTree(t, filepath.Join(second, "database"))
	if !reflect.DeepEqual(firstTree, secondTree) {
		for name, firstContent := range firstTree {
			secondContent, exists := secondTree[name]
			if !exists {
				t.Errorf("second generation is missing %s", name)
				continue
			}
			if !bytes.Equal(firstContent, secondContent) {
				t.Errorf("fixture %s differs between generations", name)
			}
		}
		for name := range secondTree {
			if _, exists := firstTree[name]; !exists {
				t.Errorf("second generation has unexpected %s", name)
			}
		}
	}
}

func readFixtureTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
