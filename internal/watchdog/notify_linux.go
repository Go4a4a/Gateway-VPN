//go:build linux

package watchdog

import (
	"errors"
	"net"
	"os"
)

func NotifySystemd(message string) error {
	if message != "READY=1" && message != "WATCHDOG=1" && message != "STOPPING=1" {
		return errors.New("unsupported fixed systemd notification")
	}
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	_, err = connection.Write([]byte(message))
	return err
}
