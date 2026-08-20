package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// DeviceID is a stable, transport-independent identifier for a device.
type DeviceID string

// Identity is a device's cryptographic identity: an Ed25519 key pair plus the
// derived device ID.
type Identity struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// Generate creates a new random Ed25519 identity.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return newIdentity(priv, pub), nil
}

// FromPrivateKey reconstructs an identity from an existing Ed25519 private key.
func FromPrivateKey(priv ed25519.PrivateKey) (*Identity, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key length %d", len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type %T", priv.Public())
	}
	return newIdentity(priv, pub), nil
}

func newIdentity(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Identity {
	return &Identity{public: pub, private: priv}
}

// PublicKey returns the device's Ed25519 public key.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.public }

// PrivateKey returns the device's Ed25519 private key.
func (i *Identity) PrivateKey() ed25519.PrivateKey { return i.private }

// DeviceID returns the stable device identifier: the hex SHA-256 of the public
// key.
func (i *Identity) DeviceID() DeviceID {
	sum := sha256.Sum256(i.public)
	return DeviceID(hex.EncodeToString(sum[:]))
}

// Fingerprint returns a short human-readable fingerprint (colon-separated hex
// of the first 8 bytes of the device ID) for pairing confirmation.
func (i *Identity) Fingerprint() string {
	sum := sha256.Sum256(i.public)
	parts := make([]string, 0, 8)
	for _, b := range sum[:8] {
		parts = append(parts, hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}
