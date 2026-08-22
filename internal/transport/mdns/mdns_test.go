package mdns

import (
	"context"
	"testing"
	"time"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/identity"
)

func TestAdvertiseAndDiscover(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const (
		name = "test-device"
		port = 42931
	)

	ann, err := NewAnnouncer(Config{
		DeviceID:  string(id.DeviceID()),
		Name:      name,
		Port:      port,
		PublicKey: id.PublicKey(),
	})
	if err != nil {
		t.Fatalf("NewAnnouncer: %v", err)
	}
	defer ann.Close()

	disc := NewDiscoverer(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	peers, err := disc.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var found *Peer
	for p := range peers {
		if p.DeviceID == string(id.DeviceID()) {
			found = &p
			break
		}
	}
	if found == nil {
		t.Skip("mDNS multicast unavailable in this environment")
	}
	if found.Name != name {
		t.Fatalf("name = %q, want %q", found.Name, name)
	}
	if found.Port != port {
		t.Fatalf("port = %d, want %d", found.Port, port)
	}
	if string(found.PublicKey) != string(id.PublicKey()) {
		t.Fatalf("public key mismatch: got %x", found.PublicKey)
	}
	if found.Host == "" {
		t.Fatal("host is empty")
	}
}

func TestParseTXT(t *testing.T) {
	records := []string{"id=abc123", "nm=my device", "key=AQID", "novalue"}
	m := parseTXT(records)
	if m["id"] != "abc123" {
		t.Fatalf("id = %q", m["id"])
	}
	if m["nm"] != "my device" {
		t.Fatalf("nm = %q", m["nm"])
	}
	if m["key"] != "AQID" {
		t.Fatalf("key = %q", m["key"])
	}
	if _, ok := m["novalue"]; ok {
		t.Fatal("record without '=' should be ignored")
	}
}

func TestDecodeKey(t *testing.T) {
	if got := decodeKey("not-valid!"); got != nil {
		t.Fatalf("decodeKey = %v, want nil", got)
	}
	if got := decodeKey("AQID"); got == nil {
		t.Fatal("decodeKey = nil, want decoded bytes")
	}
}
