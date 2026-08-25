//go:build !linux

package update

func setFileOwnership(_ string, _, _ int) error { return nil }
