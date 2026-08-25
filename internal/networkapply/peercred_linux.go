//go:build linux

package networkapply

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func LinuxPeerUID(connection net.Conn) (uint32, error) {
	syscallConnection, ok := connection.(syscall.Conn)
	if !ok {
		return 0, errors.New("broker connection does not expose syscall credentials")
	}
	raw, err := syscallConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil || credential == nil {
		return 0, socketErr
	}
	return credential.Uid, nil
}
