//go:build !linux

package vpsops

import "os"

func chownFile(_ *os.File, _, _ int) error { return nil }
