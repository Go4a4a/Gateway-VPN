//go:build !linux

package gatewayfabric

import (
	"errors"
	"os"
)

func validateRootOwned(os.FileInfo, os.FileMode) error {
	return errors.New("root ownership validation requires Linux")
}
