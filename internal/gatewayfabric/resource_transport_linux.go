//go:build linux

package gatewayfabric

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

func defaultResourceTransportProbe(ctx context.Context, network, interfaceName, address string, port int) error {
	if network != "tcp" && network != "udp" {
		return errors.New("unsupported resource transport")
	}
	if interfaceName == "" || len(interfaceName) > 15 || net.ParseIP(address) == nil {
		return errors.New("invalid resource probe interface or address")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, connection syscall.RawConn) error {
		var socketErr error
		if err := connection.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	connection, err := dialer.DialContext(ctx, network, formatResourceEndpoint(address, port))
	if err != nil {
		return err
	}
	defer connection.Close()
	if network == "udp" {
		if _, err := connection.Write(nil); err != nil {
			return err
		}
		_ = connection.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		buffer := make([]byte, 1)
		if _, err := connection.Read(buffer); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			if operation, ok := err.(*net.OpError); ok && operation.Timeout() {
				return nil
			}
			return err
		}
	}
	return nil
}
