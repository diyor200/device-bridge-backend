package device

import (
	"context"
	"testing"
	"time"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/pairing"
)

func newTestNode(t *testing.T, name string) *Node {
	t.Helper()
	n, err := New(Config{DataDir: t.TempDir(), Name: name, ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("New(%s): %v", name, err)
	}
	t.Cleanup(func() { n.Close() })
	n.PairHandler = func(pairing.Info) bool { return true }
	if err := n.Start(); err != nil {
		t.Fatalf("Start(%s): %v", name, err)
	}
	return n
}

func TestPairAndSendText(t *testing.T) {
	alice := newTestNode(t, "alice")
	bob := newTestNode(t, "bob")

	ctx := context.Background()
	bobPeer := Peer{
		DeviceID:  bob.DeviceID(),
		Name:      "bob",
		Addr:      bob.ListenAddr(),
		PublicKey: bob.PublicKey(),
	}

	if err := alice.Pair(ctx, bobPeer); err != nil {
		t.Fatalf("Pair: %v", err)
	}

	msgCh := make(chan string, 1)
	bob.MessageHandler = func(from, text string) {
		msgCh <- text
	}

	if err := alice.SendText(ctx, bob.DeviceID(), bob.ListenAddr(), "hello bob"); err != nil {
		t.Fatalf("SendText: %v", err)
	}

	select {
	case got := <-msgCh:
		if got != "hello bob" {
			t.Fatalf("message = %q, want %q", got, "hello bob")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestSendTextToUntrustedPeerFails(t *testing.T) {
	alice := newTestNode(t, "alice")
	bob := newTestNode(t, "bob")

	ctx := context.Background()
	if err := alice.SendText(ctx, bob.DeviceID(), bob.ListenAddr(), "should fail"); err == nil {
		t.Fatal("expected SendText to fail without pairing")
	}
}
