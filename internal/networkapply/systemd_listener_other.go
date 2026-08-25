//go:build !linux

package networkapply

import (
	"errors"
	"net"
)

func ListenerFromSystemdFD(uintptr, uint32) (net.Listener, error) {
	return nil, errors.New("systemd socket activation is available only on Linux")
}
