// Package tcp provides the LAN transport: TLS 1.3 over TCP with length-prefixed
// framing for the control and data channels.
package tcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/identity"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/transport"
)

// Config configures the TCP/TLS transport.
type Config struct {
	// Identity is the local device identity used for the TLS certificate.
	Identity *identity.Identity
	// Trust decides which peer public keys are accepted.
	Trust transport.TrustStore
	// HandshakeTimeout bounds dialing and TLS handshakes. Zero means 10s.
	HandshakeTimeout time.Duration
}

// Transport is a TLS 1.3-over-TCP implementation of transport.Transport.
type Transport struct {
	cfg    Config
	tlsCfg *tls.Config
}

// New returns a TCP transport with TLS mutual authentication based on pinned
// device keys.
func New(cfg Config) (*Transport, error) {
	if cfg.Identity == nil {
		return nil, errors.New("tcp: identity is required")
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Transport{cfg: cfg, tlsCfg: tlsCfg}, nil
}

// Connect dials peer.Addr and performs the TLS handshake as a client.
func (t *Transport) Connect(ctx context.Context, peer transport.Peer) (transport.Connection, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: t.cfg.HandshakeTimeout},
		Config:    t.tlsCfg,
	}
	raw, err := d.DialContext(ctx, "tcp", peer.Addr)
	if err != nil {
		return nil, fmt.Errorf("tcp: dial %s: %w", peer.Addr, err)
	}
	tc, ok := raw.(*tls.Conn)
	if !ok {
		raw.Close()
		return nil, errors.New("tcp: unexpected connection type")
	}
	return &conn{Conn: tc}, nil
}

// Listen starts accepting TLS connections on addr.
func (t *Transport) Listen(addr string) (transport.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp: listen %s: %w", addr, err)
	}
	return &listener{ln: ln, tlsCfg: t.tlsCfg, timeout: t.cfg.HandshakeTimeout}, nil
}

// buildTLSConfig returns a TLS 1.3 config for both client and server roles.
// Normal chain verification is replaced by VerifyPeerCertificate, which checks
// the peer's self-signed certificate against the trust store.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	cert, err := cfg.Identity.SelfSignedCertificate()
	if err != nil {
		return nil, fmt.Errorf("tcp: load certificate: %w", err)
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true, // verification is done in VerifyPeerCertificate
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPeer(cfg.Trust),
	}, nil
}

// verifyPeer returns the TLS callback that authenticates a peer certificate:
// self-signed and present in the trust store.
func verifyPeer(trust transport.TrustStore) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("tcp: peer presented no certificate")
		}
		pub, err := identity.SelfSignedPublicKey(rawCerts[0])
		if err != nil {
			return err
		}
		if trust == nil || !trust.Trusted(pub) {
			return errors.New("tcp: peer public key is not trusted")
		}
		return nil
	}
}
