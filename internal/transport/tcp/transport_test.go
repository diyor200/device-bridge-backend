package tcp

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/identity"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/protocol"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/transport"
)

func TestMutualTLSAndHello(t *testing.T) {
	alice, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate alice: %v", err)
	}
	bob, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate bob: %v", err)
	}

	aliceTr, err := New(Config{
		Identity: alice,
		Trust:    transport.TrustStoreFunc(func(p ed25519.PublicKey) bool { return p.Equal(bob.PublicKey()) }),
	})
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	bobTr, err := New(Config{
		Identity: bob,
		Trust:    transport.TrustStoreFunc(func(p ed25519.PublicKey) bool { return p.Equal(alice.PublicKey()) }),
	})
	if err != nil {
		t.Fatalf("New bob: %v", err)
	}

	ln, err := aliceTr.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	type acceptResult struct {
		c   transport.Connection
		err error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		acceptCh <- acceptResult{c, err}
	}()

	bobConn, err := bobTr.Connect(context.Background(), transport.Peer{Addr: ln.Addr().String()})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer bobConn.Close()

	ar := <-acceptCh
	if ar.err != nil {
		t.Fatalf("Accept: %v", ar.err)
	}
	aliceConn := ar.c
	defer aliceConn.Close()

	if got := bobConn.PeerDeviceID(); got != string(alice.DeviceID()) {
		t.Fatalf("bob sees peer %q, want %q", got, alice.DeviceID())
	}
	if got := aliceConn.PeerDeviceID(); got != string(bob.DeviceID()) {
		t.Fatalf("alice sees peer %q, want %q", got, bob.DeviceID())
	}

	aliceCh := protocol.NewControlChannel(aliceConn, protocol.JSONCodec{})
	bobCh := protocol.NewControlChannel(bobConn, protocol.JSONCodec{})

	hello, err := protocol.NewMessage(protocol.TypeHello, protocol.Hello{
		DeviceID: string(bob.DeviceID()), Name: "bob", Version: protocol.Version,
	})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if err := bobCh.Send(hello); err != nil {
		t.Fatalf("bob Send: %v", err)
	}
	got, err := aliceCh.Receive()
	if err != nil {
		t.Fatalf("alice Receive: %v", err)
	}
	if got.Type != protocol.TypeHello {
		t.Fatalf("received type %q, want %q", got.Type, protocol.TypeHello)
	}
	var h protocol.Hello
	if err := got.DecodePayload(&h); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if h.DeviceID != string(bob.DeviceID()) || h.Name != "bob" {
		t.Fatalf("decoded hello = %+v", h)
	}
}

func TestUntrustedPeerRejected(t *testing.T) {
	alice, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate alice: %v", err)
	}
	mallory, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate mallory: %v", err)
	}

	aliceTr, err := New(Config{
		Identity: alice,
		Trust:    transport.TrustStoreFunc(func(p ed25519.PublicKey) bool { return false }),
	})
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	malloryTr, err := New(Config{
		Identity: mallory,
		Trust:    transport.TrustStoreFunc(func(p ed25519.PublicKey) bool { return p.Equal(alice.PublicKey()) }),
	})
	if err != nil {
		t.Fatalf("New mallory: %v", err)
	}

	ln, err := aliceTr.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	acceptErrCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		acceptErrCh <- err
	}()

	// In TLS 1.3 the client may complete its handshake before the server
	// rejects the untrusted certificate, so Connect may or may not error here.
	// The server-side rejection below is the real security check.
	malloryConn, err := malloryTr.Connect(context.Background(), transport.Peer{Addr: ln.Addr().String()})
	if err != nil {
		t.Logf("Connect failed early: %v", err)
	} else {
		malloryConn.Close()
	}

	if err := <-acceptErrCh; err == nil {
		t.Fatal("expected server to reject untrusted peer")
	}
}
