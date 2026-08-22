package pairing

import (
	"crypto/ed25519"
	"net"
	"path/filepath"
	"testing"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/identity"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/protocol"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/storage"
)

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "trust.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestExchangeAndConfirm(t *testing.T) {
	alice, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate alice: %v", err)
	}
	bob, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate bob: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	dialer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dialer.Close()

	var listener net.Conn
	select {
	case listener = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("Accept: %v", err)
	}
	defer listener.Close()

	aliceStore := newStore(t)
	bobStore := newStore(t)

	aliceSess := NewSession(dialer, alice, aliceStore)
	bobSess := NewSession(listener, bob, bobStore)

	var alicePeer, bobPeer Info
	var aliceErr, bobErr error
	done := make(chan struct{}, 2)
	go func() {
		alicePeer, aliceErr = aliceSess.Exchange("alice-device")
		done <- struct{}{}
	}()
	go func() {
		bobPeer, bobErr = bobSess.Exchange("bob-device")
		done <- struct{}{}
	}()
	<-done
	<-done

	if aliceErr != nil {
		t.Fatalf("alice Exchange: %v", aliceErr)
	}
	if bobErr != nil {
		t.Fatalf("bob Exchange: %v", bobErr)
	}

	if alicePeer.DeviceID != string(bob.DeviceID()) || alicePeer.Name != "bob-device" {
		t.Fatalf("alice sees peer %+v", alicePeer)
	}
	if bobPeer.DeviceID != string(alice.DeviceID()) || bobPeer.Name != "alice-device" {
		t.Fatalf("bob sees peer %+v", bobPeer)
	}
	if string(alicePeer.PublicKey) != string(bob.PublicKey()) {
		t.Fatal("alice received wrong public key")
	}

	if err := aliceSess.Confirm(); err != nil {
		t.Fatalf("alice Confirm: %v", err)
	}
	if err := bobSess.Confirm(); err != nil {
		t.Fatalf("bob Confirm: %v", err)
	}

	if !aliceStore.Trusted(bob.PublicKey()) {
		t.Fatal("alice does not trust bob after confirm")
	}
	if !bobStore.Trusted(alice.PublicKey()) {
		t.Fatal("bob does not trust alice after confirm")
	}
}

func TestConfirmWithoutExchange(t *testing.T) {
	alice, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	c1, _ := net.Pipe()
	defer c1.Close()

	sess := NewSession(c1, alice, newStore(t))
	if err := sess.Confirm(); err == nil {
		t.Fatal("expected Confirm to fail without an exchange")
	}
}

func TestVerifyIdentity(t *testing.T) {
	alice, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cert, err := alice.CertificateDER()
	if err != nil {
		t.Fatalf("CertificateDER: %v", err)
	}
	good := protocolPair(alice, "alice-device", cert)

	if err := verifyIdentity(&good); err != nil {
		t.Fatalf("verifyIdentity (good): %v", err)
	}

	tampered := good
	tampered.DeviceID = "deadbeef"
	if err := verifyIdentity(&tampered); err == nil {
		t.Fatal("expected device ID mismatch to fail")
	}

	missingCert := good
	missingCert.Certificate = nil
	if err := verifyIdentity(&missingCert); err == nil {
		t.Fatal("expected missing certificate to fail")
	}

	badCert := good
	badCert.Certificate = []byte("not a certificate")
	if err := verifyIdentity(&badCert); err == nil {
		t.Fatal("expected invalid certificate to fail")
	}
}

func protocolPair(id *identity.Identity, name string, cert []byte) protocol.Pair {
	return protocol.Pair{
		DeviceID:    string(id.DeviceID()),
		Name:        name,
		PublicKey:   ed25519.PublicKey(id.PublicKey()),
		Certificate: cert,
	}
}
