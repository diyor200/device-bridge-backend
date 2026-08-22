package transport

import "crypto/ed25519"

// TrustStore decides whether a peer's public key is trusted. Implementations
// are typically backed by the pairing trust store.
type TrustStore interface {
	Trusted(pub ed25519.PublicKey) bool
}

// TrustStoreFunc adapts a function to the TrustStore interface.
type TrustStoreFunc func(pub ed25519.PublicKey) bool

// Trusted calls f.
func (f TrustStoreFunc) Trusted(pub ed25519.PublicKey) bool { return f(pub) }
