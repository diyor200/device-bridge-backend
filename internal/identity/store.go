package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const (
	keyFileName  = "identity.key"
	certFileName = "identity.crt"
)

// Save persists the identity (private key and self-signed certificate) to dir.
func (i *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(i.private)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, keyFileName), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	cert, err := i.CertificatePEM()
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFileName), cert, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	return nil
}

// Load reads a persisted identity from dir. The private key is required; the
// certificate is regenerated on demand if absent.
func Load(dir string) (*Identity, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode key: no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519.PrivateKey", parsed)
	}
	return FromPrivateKey(priv)
}

// LoadOrCreate returns the persisted identity at dir, or generates and saves a
// new one.
func LoadOrCreate(dir string) (*Identity, error) {
	if id, err := Load(dir); err == nil {
		return id, nil
	}
	id, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := id.Save(dir); err != nil {
		return nil, fmt.Errorf("save generated identity: %w", err)
	}
	return id, nil
}
