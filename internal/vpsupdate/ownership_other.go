//go:build !linux

package vpsupdate

func chownPath(_ string, _, _ int) error { return nil }
