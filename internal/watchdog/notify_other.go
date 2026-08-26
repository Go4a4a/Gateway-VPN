//go:build !linux

package watchdog

import "errors"

func NotifySystemd(message string) error {
	if message != "READY=1" && message != "WATCHDOG=1" && message != "STOPPING=1" {
		return errors.New("unsupported fixed systemd notification")
	}
	return nil
}
