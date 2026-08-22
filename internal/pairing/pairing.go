// Package pairing implements the pairing handshake (identity exchange, pinning,
// confirmation) and the trust store backed by SQLite.
package pairing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/identity"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/protocol"
)

// Info describes a verified peer after the pairing exchange.
type Info struct {
	DeviceID  string
	Name      string
	PublicKey ed25519.PublicKey
}

// Store persists trusted peers.
type Store interface {
	AddPeer(deviceID, name string, pub ed25519.PublicKey) error
}

// Verify checks that p is self-consistent (device ID is the hash of the public
// key, and the certificate is self-signed by that key) and returns its Info.
func Verify(p *protocol.Pair) (Info, error) {
	if err := verifyIdentity(p); err != nil {
		return Info{}, err
	}
	return Info{DeviceID: p.DeviceID, Name: p.Name, PublicKey: p.PublicKey}, nil
}

// Session runs the pairing handshake over an established connection. The
// connection is expected to already be encrypted and authenticated by the
// transport layer (TLS with pinned keys); the exchange here verifies the peer's
// self-consistency (device ID, public key, and certificate).
type Session struct {
	ch    *protocol.ControlChannel
	self  *identity.Identity
	store Store
	peer  Info
}

// NewSession returns a pairing session over rw for identity self.
func NewSession(rw io.ReadWriter, self *identity.Identity, store Store) *Session {
	return &Session{
		ch:    protocol.NewControlChannel(rw, protocol.JSONCodec{}),
		self:  self,
		store: store,
	}
}

// Exchange sends our identity and receives and verifies the peer's identity,
// returning it. It is the initiator side (send first, then receive).
func (s *Session) Exchange(name string) (Info, error) {
	if err := s.sendIdentity(name); err != nil {
		return Info{}, err
	}
	resp, err := s.ch.Receive()
	if err != nil {
		return Info{}, fmt.Errorf("pairing: receive: %w", err)
	}
	if resp.Type != protocol.TypePair {
		return Info{}, fmt.Errorf("pairing: unexpected message type %q", resp.Type)
	}
	var p protocol.Pair
	if err := resp.DecodePayload(&p); err != nil {
		return Info{}, fmt.Errorf("pairing: decode: %w", err)
	}
	info, err := Verify(&p)
	if err != nil {
		return Info{}, err
	}
	s.peer = info
	return info, nil
}

// Confirm persists the peer from the last successful exchange as trusted.
func (s *Session) Confirm() error {
	if s.peer.DeviceID == "" {
		return fmt.Errorf("pairing: no peer exchanged to confirm")
	}
	return s.store.AddPeer(s.peer.DeviceID, s.peer.Name, s.peer.PublicKey)
}

func (s *Session) sendIdentity(name string) error {
	cert, err := s.self.CertificateDER()
	if err != nil {
		return fmt.Errorf("pairing: certificate: %w", err)
	}
	msg, err := protocol.NewMessage(protocol.TypePair, protocol.Pair{
		DeviceID:    string(s.self.DeviceID()),
		Name:        name,
		PublicKey:   s.self.PublicKey(),
		Certificate: cert,
	})
	if err != nil {
		return fmt.Errorf("pairing: build message: %w", err)
	}
	if err := s.ch.Send(msg); err != nil {
		return fmt.Errorf("pairing: send: %w", err)
	}
	return nil
}

// verifyIdentity checks that the peer's claimed identity is self-consistent:
// the device ID is the hash of the public key, and the certificate is
// self-signed by that key.
func verifyIdentity(p *protocol.Pair) error {
	sum := sha256.Sum256(p.PublicKey)
	if hex.EncodeToString(sum[:]) != p.DeviceID {
		return fmt.Errorf("pairing: device ID does not match public key")
	}
	if len(p.Certificate) == 0 {
		return fmt.Errorf("pairing: missing certificate")
	}
	if err := identity.VerifyPinnedCert(p.PublicKey, p.Certificate); err != nil {
		return fmt.Errorf("pairing: %w", err)
	}
	return nil
}
