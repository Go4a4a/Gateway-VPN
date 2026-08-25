package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"go.yaml.in/yaml/v3"
)

const MaxFileSize = 1 << 20

func Load(filename string) (Config, error) {
	if filename == "" {
		return Config{}, errors.New("config filename is required")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Config{}, errors.New("config file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("config path must be a regular file")
	}
	if info.Size() > MaxFileSize {
		return Config{}, fmt.Errorf("config file exceeds %d bytes", MaxFileSize)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("config file must not be writable by group or others")
	}

	file, err := os.Open(filename)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, MaxFileSize+1)
	decoder := yaml.NewDecoder(limited)
	decoder.KnownFields(true)
	config := Default()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("config must contain exactly one YAML document")
		}
		return Config{}, fmt.Errorf("decode trailing config document: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return config, nil
}
