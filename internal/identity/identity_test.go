package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestGenerate(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(id.PublicKey()) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(id.PublicKey()), ed25519.PublicKeySize)
	}
	if len(id.PrivateKey()) != ed25519.PrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(id.PrivateKey()), ed25519.PrivateKeySize)
	}
	if !bytes.Equal(id.PublicKey(), id.PrivateKey().Public().(ed25519.PublicKey)) {
		t.Fatal("public key does not match private key")
	}
	if len(id.DeviceID()) != 64 {
		t.Fatalf("device ID length = %d, want 64", len(id.DeviceID()))
	}
	if _, err := hex.DecodeString(string(id.DeviceID())); err != nil {
		t.Fatalf("device ID is not hex: %v", err)
	}
}

func TestDeviceIDMatchesPublicKeyHash(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sum := sha256.Sum256(id.PublicKey())
	want := DeviceID(hex.EncodeToString(sum[:]))
	if id.DeviceID() != want {
		t.Fatalf("DeviceID = %q, want %q", id.DeviceID(), want)
	}
}

func TestFingerprintFormat(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fp := id.Fingerprint()
	if len(fp) != 23 { // 8 bytes -> 8*2 hex + 7 colons
		t.Fatalf("fingerprint %q length = %d, want 23", fp, len(fp))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := id.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DeviceID() != id.DeviceID() {
		t.Fatalf("DeviceID = %q, want %q", got.DeviceID(), id.DeviceID())
	}
	if !bytes.Equal(got.PublicKey(), id.PublicKey()) {
		t.Fatal("public key changed after round trip")
	}
	if !bytes.Equal(got.PrivateKey(), id.PrivateKey()) {
		t.Fatal("private key changed after round trip")
	}
}

func TestLoadOrCreatePersists(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate (first): %v", err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate (second): %v", err)
	}
	if first.DeviceID() != second.DeviceID() {
		t.Fatalf("identity regenerated on second load: %q != %q", first.DeviceID(), second.DeviceID())
	}
}

func TestSelfSignedCertificate(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cert, err := id.SelfSignedCertificate()
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("certificate is not self-signed: %v", err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("cert public key is %T, want ed25519.PublicKey", leaf.PublicKey)
	}
	if !pub.Equal(id.PublicKey()) {
		t.Fatal("certificate public key does not match identity")
	}
}

func TestCertificatePEM(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pemBytes, err := id.CertificatePEM()
	if err != nil {
		t.Fatalf("CertificatePEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM type = %q, want CERTIFICATE", block.Type)
	}
}

func TestVerifyPinnedCert(t *testing.T) {
	alice, err := Generate()
	if err != nil {
		t.Fatalf("Generate alice: %v", err)
	}
	bob, err := Generate()
	if err != nil {
		t.Fatalf("Generate bob: %v", err)
	}

	aliceDER := mustSelfSignedDER(t, alice)

	if err := VerifyPinnedCert(alice.PublicKey(), aliceDER); err != nil {
		t.Fatalf("VerifyPinnedCert (matching key): %v", err)
	}
	if err := VerifyPinnedCert(bob.PublicKey(), aliceDER); err == nil {
		t.Fatal("VerifyPinnedCert (mismatched key): expected error")
	}
}

func mustSelfSignedDER(t *testing.T, id *Identity) []byte {
	t.Helper()
	der, err := id.selfSignedDER()
	if err != nil {
		t.Fatalf("selfSignedDER: %v", err)
	}
	return der
}
