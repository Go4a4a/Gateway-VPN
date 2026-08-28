//go:build !linux

package ethernet

import (
	"context"
	"errors"
)

type unsupportedProbe struct{}

func HostProbe([]byte) Probe { return unsupportedProbe{} }

func (unsupportedProbe) List(context.Context) ([]Device, error) {
	return nil, errors.New("Ethernet observation requires Ubuntu/Linux")
}
