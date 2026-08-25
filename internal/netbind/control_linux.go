//go:build linux

package netbind

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func SocketControl(configuration Config) func(string, string, syscall.RawConn) error {
	return func(_, _ string, connection syscall.RawConn) error {
		if err := configuration.Validate(); err != nil {
			return err
		}
		var socketErr error
		if err := connection.Control(func(descriptor uintptr) {
			if err := unix.SetsockoptString(int(descriptor), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, configuration.InterfaceName); err != nil {
				socketErr = err
				return
			}
			if err := unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_MARK, int(configuration.Fwmark)); err != nil {
				socketErr = err
			}
		}); err != nil {
			return err
		}
		if socketErr != nil {
			return errors.New("bind socket to modem routing context failed")
		}
		return nil
	}
}
