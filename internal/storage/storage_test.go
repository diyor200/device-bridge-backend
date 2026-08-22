package storage

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}

func TestPeerLifecycle(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	pub := mustKey(t)
	if s.Trusted(pub) {
		t.Fatal("unexpected trust before add")
	}

	if err := s.AddPeer("id1", "alice", pub); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if !s.Trusted(pub) {
		t.Fatal("peer not trusted after add")
	}

	peers, err := s.Peers()
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(peers))
	}
	if peers[0].DeviceID != "id1" || peers[0].Name != "alice" {
		t.Fatalf("peer = %+v", peers[0])
	}
	if string(peers[0].PublicKey) != string(pub) {
		t.Fatal("public key mismatch")
	}

	if err := s.RemovePeer("id1"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if s.Trusted(pub) {
		t.Fatal("peer still trusted after remove")
	}
}

func TestAddPeerUpsert(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	pub := mustKey(t)
	if err := s.AddPeer("id1", "old-name", pub); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := s.AddPeer("id1", "new-name", pub); err != nil {
		t.Fatalf("AddPeer upsert: %v", err)
	}

	peers, err := s.Peers()
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers = %d, want 1 after upsert", len(peers))
	}
	if peers[0].Name != "new-name" {
		t.Fatalf("name = %q, want new-name", peers[0].Name)
	}
}

func TestPersistenceAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pub := mustKey(t)
	if err := s.AddPeer("id1", "alice", pub); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("Open (reopen): %v", err)
	}
	defer s.Close()
	if !s.Trusted(pub) {
		t.Fatal("peer not trusted after reopen")
	}
}
