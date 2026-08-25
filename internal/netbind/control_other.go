//go:build !linux

package netbind

import (
	"errors"
	"syscall"
)

func SocketControl(configuration Config) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		if err := configuration.Validate(); err != nil {
			return err
		}
		return errors.New("modem-bound sockets require Ubuntu/Linux")
	}
}
