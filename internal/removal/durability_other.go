//go:build !linux

package removal

// Directory fsync is a Linux production durability boundary. Windows builds
// exist only for source/unit tests and os.File.Sync on a directory is rejected.
func syncDirectory(string) error { return nil }
