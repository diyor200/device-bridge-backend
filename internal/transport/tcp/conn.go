package tcp

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/transport"
)

// conn is a TLS connection to a peer, implementing transport.Connection.
type conn struct {
	*tls.Conn
}

// PeerDeviceID returns the remote device ID from the verified peer certificate.
func (c *conn) PeerDeviceID() string {
	state := c.Conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// listener accepts TLS connections, performing the handshake eagerly so that
// untrusted peers are rejected before a connection is returned.
type listener struct {
	ln      net.Listener
	tlsCfg  *tls.Config
	timeout time.Duration
}

// Accept waits for and returns the next authenticated connection.
func (l *listener) Accept() (transport.Connection, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	tc := tls.Server(raw, l.tlsCfg)
	_ = raw.SetDeadline(time.Now().Add(l.timeout))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return &conn{Conn: tc}, nil
}

// Close closes the listener.
func (l *listener) Close() error { return l.ln.Close() }

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr { return l.ln.Addr() }
