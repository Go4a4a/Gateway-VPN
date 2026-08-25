//go:build linux

package hilink

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

type NetlinkLinkWatcher struct{}

func HostLinkWatcher() LinkWatcher { return NetlinkLinkWatcher{} }

func (NetlinkLinkWatcher) Watch(ctx context.Context, events chan<- struct{}) error {
	if events == nil {
		return errors.New("link event channel is required")
	}
	descriptor, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open route netlink socket: %w", err)
	}
	defer unix.Close(descriptor)
	if err := unix.Bind(descriptor, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}); err != nil {
		return fmt.Errorf("subscribe to link netlink group: %w", err)
	}
	timeout := unix.NsecToTimeval(time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(descriptor, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return fmt.Errorf("bound netlink receive timeout: %w", err)
	}
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		count, _, err := unix.Recvfrom(descriptor, buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("receive route netlink event: %w", err)
		}
		if count == 0 {
			continue
		}
		select {
		case events <- struct{}{}:
		default:
		}
	}
}
