//go:build !linux

package networkapply

import (
	"errors"
	"net"
)

func LinuxPeerUID(net.Conn) (uint32, error) {
	return 0, errors.New("SO_PEERCRED is available only on Linux")
}
