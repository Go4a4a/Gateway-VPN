//go:build !linux

package gatewayfabric

import (
	"context"
	"errors"
)

func defaultResourceTransportProbe(context.Context, string, string, string, int) error {
	return errors.New("resource transport probes are available only on Linux")
}
