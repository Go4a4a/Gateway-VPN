//go:build !linux

package hilink

import (
	"context"
	"errors"
)

type unsupportedProbe struct{}

func HostProbe() Probe { return unsupportedProbe{} }

func (unsupportedProbe) ListUSBNetworkDevices(context.Context) ([]RawDevice, error) {
	return nil, errors.New("HiLink sysfs discovery requires Ubuntu/Linux")
}
