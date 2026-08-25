//go:build linux

package networkapply

import (
	"errors"
	"net"
	"os"
)

func ListenerFromSystemdFD(fd uintptr, allowedUID uint32) (net.Listener, error) {
	if fd < 3 {
		return nil, errors.New("systemd socket file descriptor must be at least 3")
	}
	file := os.NewFile(fd, "gateway-vpn-network-broker.socket")
	if file == nil {
		return nil, errors.New("open systemd socket file descriptor failed")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	if listener.Addr().Network() != "unix" {
		listener.Close()
		return nil, errors.New("network broker systemd socket must be Unix-domain")
	}
	return &PeerAuthorizingListener{Listener: listener, AllowedUID: allowedUID, PeerUID: LinuxPeerUID}, nil
}
