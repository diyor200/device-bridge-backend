// Package transport defines the Transport and Connection abstractions so the
// protocol and application layers are independent of the underlying network
// (LAN TCP today, P2P/relay later).
package transport

import (
	"context"
	"io"
	"net"
)

// Peer identifies a remote device and how to reach it.
type Peer struct {
	DeviceID string
	Name     string
	Addr     string // "host:port"
}

// Connection is an encrypted byte stream to a peer. Control and data channels
// are built on top of it by the protocol and files packages.
type Connection interface {
	io.ReadWriter
	Close() error
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	// PeerDeviceID returns the authenticated remote device ID, extracted from
	// the peer's verified certificate.
	PeerDeviceID() string
}

// Listener accepts incoming encrypted connections.
type Listener interface {
	Accept() (Connection, error)
	Close() error
	Addr() net.Addr
}

// Transport dials peers and listens for incoming connections. Implementations
// handle the encryption and authentication (e.g. TLS with pinned keys).
type Transport interface {
	Connect(ctx context.Context, peer Peer) (Connection, error)
	Listen(addr string) (Listener, error)
}
