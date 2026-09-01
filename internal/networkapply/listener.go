package networkapply

import (
	"errors"
	"net"
)

var ErrUnauthorizedBrokerPeer = errors.New("network broker peer UID is not authorized")

type PeerUIDFunc func(net.Conn) (uint32, error)

// PeerAuthorizingListener rejects connections before HTTP parsing. Socket
// filesystem permissions are the first boundary; SO_PEERCRED is the second.
type PeerAuthorizingListener struct {
	net.Listener
	AllowedUID uint32
	AllowRoot  bool
	PeerUID    PeerUIDFunc
}

func (listener *PeerAuthorizingListener) Accept() (net.Conn, error) {
	if listener == nil || listener.Listener == nil || listener.PeerUID == nil {
		return nil, errors.New("peer-authorizing listener is not configured")
	}
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := listener.PeerUID(connection)
		if err == nil && (uid == listener.AllowedUID || (listener.AllowRoot && uid == 0)) {
			return connection, nil
		}
		_ = connection.Close()
		if err != nil {
			return nil, err
		}
		// Reject the unauthorized connection and continue accepting without
		// exposing an HTTP error oracle on the privileged socket.
	}
}
