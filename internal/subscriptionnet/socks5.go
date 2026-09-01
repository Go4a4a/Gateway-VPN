package subscriptionnet

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/subscription"
)

const socksHandshakeTimeout = 10 * time.Second

// newSOCKS5Dialer creates an unauthenticated SOCKS5 client for Mihomo's
// numeric loopback-only mixed listener. The caller must serialize selector
// changes with every connection created through this dialer.
func newSOCKS5Dialer(listenerAddress string) (subscription.DialContextFunc, error) {
	listener, err := netip.ParseAddrPort(listenerAddress)
	if err != nil || !listener.Addr().IsLoopback() || listener.Port() == 0 {
		return nil, errors.New("subscription proxy listener must be a numeric loopback address with a port")
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" {
			return nil, errors.New("subscription proxy supports TCP only")
		}
		host, rawPort, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("subscription proxy destination is invalid")
		}
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("subscription proxy destination port is invalid")
		}
		dialer := &net.Dialer{Timeout: socksHandshakeTimeout, KeepAlive: 15 * time.Second}
		connection, err := dialer.DialContext(ctx, "tcp", listener.String())
		if err != nil {
			return nil, errors.New("subscription proxy listener is unavailable")
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = connection.SetDeadline(deadline)
		} else {
			_ = connection.SetDeadline(time.Now().Add(socksHandshakeTimeout))
		}
		if err := socks5Connect(connection, host, uint16(port)); err != nil {
			connection.Close()
			return nil, err
		}
		_ = connection.SetDeadline(time.Time{})
		return connection, nil
	}, nil
}

// NewSOCKS5Dialer exposes the same loopback-only, unauthenticated Mihomo
// service dialer to other control-plane route ladders. It does not select a
// proxy and must be used while the shared selector operation lock is held.
func NewSOCKS5Dialer(listenerAddress string) (subscription.DialContextFunc, error) {
	return newSOCKS5Dialer(listenerAddress)
}

func socks5Connect(connection net.Conn, host string, port uint16) error {
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return errors.New("subscription proxy greeting failed")
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || response[0] != 5 || response[1] != 0 {
		return errors.New("subscription proxy authentication negotiation failed")
	}
	request := []byte{5, 1, 0}
	address, addressErr := netip.ParseAddr(strings.Trim(host, "[]"))
	switch {
	case addressErr == nil && address.Unmap().Is4():
		request = append(request, 1)
		value := address.Unmap().As4()
		request = append(request, value[:]...)
	case addressErr == nil && address.Is6():
		request = append(request, 4)
		value := address.As16()
		request = append(request, value[:]...)
	case host != "" && len(host) <= 253 && !strings.ContainsAny(host, "\x00\r\n"):
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	default:
		return errors.New("subscription proxy destination host is invalid")
	}
	request = binary.BigEndian.AppendUint16(request, port)
	if _, err := connection.Write(request); err != nil {
		return errors.New("subscription proxy connect request failed")
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 || header[2] != 0 {
		return errors.New("subscription proxy connect response is invalid")
	}
	if header[1] != 0 {
		return errors.New("subscription proxy route rejected the destination")
	}
	addressLength := 0
	switch header[3] {
	case 1:
		addressLength = 4
	case 4:
		addressLength = 16
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil || length[0] == 0 {
			return errors.New("subscription proxy response address is invalid")
		}
		addressLength = int(length[0])
	default:
		return errors.New("subscription proxy response address type is invalid")
	}
	trailer := make([]byte, addressLength+2)
	if _, err := io.ReadFull(connection, trailer); err != nil {
		return errors.New("subscription proxy response is incomplete")
	}
	return nil
}

func proxyResolver(dial subscription.DialContextFunc, bootstrapDNS []string) subscription.Resolver {
	return &ipv4OnlyResolver{inner: &net.Resolver{
		PreferGo: true, StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			connection, err := dial(ctx, "tcp4", net.JoinHostPort(bootstrapDNS[0], "53"))
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(network, "udp") {
				return &dnsTCPPacketConn{Conn: connection}, nil
			}
			return connection, nil
		},
	}}
}

// NewProxyResolver keeps DNS inside the already selected Mihomo service route
// and never falls back to the host resolver.
func NewProxyResolver(dial subscription.DialContextFunc, bootstrapDNS []string) subscription.Resolver {
	return proxyResolver(dial, bootstrapDNS)
}

// dnsTCPPacketConn presents a DNS-over-TCP stream as the packet-shaped Conn
// expected by net.Resolver's UDP path. This prevents any local/direct DNS
// fallback while still using the standard library DNS parser and validation.
type dnsTCPPacketConn struct {
	net.Conn
}

func (connection *dnsTCPPacketConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 || len(payload) > 65535 {
		return 0, errors.New("proxied DNS request size is invalid")
	}
	framed := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(payload)))
	copy(framed[2:], payload)
	if _, err := connection.Conn.Write(framed); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (connection *dnsTCPPacketConn) Read(payload []byte) (int, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection.Conn, header); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(header))
	if length == 0 {
		return 0, errors.New("proxied DNS response is empty")
	}
	if length > len(payload) {
		if _, err := io.CopyN(io.Discard, connection.Conn, int64(length)); err != nil {
			return 0, err
		}
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(connection.Conn, payload[:length])
}
