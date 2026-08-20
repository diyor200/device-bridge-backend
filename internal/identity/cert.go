package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// certValidity is how long self-signed certificates are valid. Peers pin the
// public key (not the certificate), so renewal is transparent.
const certValidity = 10 * 365 * 24 * time.Hour

// selfSignedDER generates a fresh self-signed certificate for the identity's
// public key, signed by its private key, and returns the DER bytes.
func (i *Identity) selfSignedDER() ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: string(i.DeviceID())},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, i.public, i.private)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return der, nil
}

// SelfSignedCertificate returns a tls.Certificate for the identity, generating
// a fresh self-signed certificate on demand.
func (i *Identity) SelfSignedCertificate() (tls.Certificate, error) {
	der, err := i.selfSignedDER()
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(i.private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// CertificatePEM returns the leaf certificate in PEM form, suitable for
// persistence and for exchange during pairing.
func (i *Identity) CertificatePEM() ([]byte, error) {
	der, err := i.selfSignedDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// VerifyPinnedCert checks that a peer-presented certificate (DER) is self-signed
// and belongs to the pinned public key. It is used by the TLS verification
// callback to authenticate a paired peer.
func VerifyPinnedCert(pinned ed25519.PublicKey, certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("peer certificate is not self-signed: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("peer certificate public key is %T, want ed25519.PublicKey", cert.PublicKey)
	}
	if !pub.Equal(pinned) {
		return fmt.Errorf("peer certificate public key does not match pinned key")
	}
	return nil
}
