// Package buildinfo exposes values populated by release linker flags.
package buildinfo

import "fmt"

var (
	Version       = "0.0.0-dev"
	Commit        = "unknown"
	Date          = "unknown"
	MihomoVersion = "unknown"
)

func String(component string) string {
	return fmt.Sprintf("%s %s (commit=%s, built=%s, mihomo=%s)", component, Version, Commit, Date, MihomoVersion)
}
