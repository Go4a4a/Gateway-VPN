//go:build !windows

package endurance

import "os"

func replaceEnduranceFile(source, destination string) error {
	return os.Rename(source, destination)
}
