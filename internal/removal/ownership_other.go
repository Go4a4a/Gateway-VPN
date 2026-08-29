//go:build !linux

package removal

import "os"

// Non-Linux builds exist only for source/unit tests. Production initialization
// is separately rejected outside Linux by the application runtime.
func isRootOwned(os.FileInfo) bool { return true }

// Windows does not preserve Unix directory permission bits consistently.
// Linux production builds retain the exact 0700/0600 checks in ownership_linux.go.
func hasSecureMode(os.FileInfo, os.FileMode) bool { return true }
