//go:build !linux

package hilink

import (
	"context"
	"errors"
)

type unsupportedLinkWatcher struct{}

func HostLinkWatcher() LinkWatcher { return unsupportedLinkWatcher{} }

func (unsupportedLinkWatcher) Watch(context.Context, chan<- struct{}) error {
	return errors.New("HiLink link events require Ubuntu/Linux")
}
