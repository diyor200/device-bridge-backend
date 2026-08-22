// Package mdns implements mDNS/Bonjour device discovery on the local network.
package mdns

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/grandcat/zeroconf"
)

const (
	// ServiceType is the DNS-SD service type used to advertise devices.
	ServiceType = "_devicebridge._tcp"
	// Domain is the mDNS domain.
	Domain = "local."
)

// Peer is a device discovered on the local network.
type Peer struct {
	DeviceID  string
	Name      string
	Host      string
	Port      int
	PublicKey []byte
}

// Addr returns the peer's host:port address, suitable for a TCP dial.
func (p Peer) Addr() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

// Config configures a device advertisement.
type Config struct {
	DeviceID  string
	Name      string
	Port      int
	PublicKey []byte
	Ifaces    []net.Interface // nil means all interfaces
}

// Announcer advertises the local device on the network.
type Announcer struct {
	server *zeroconf.Server
}

// NewAnnouncer registers the device with mDNS.
func NewAnnouncer(cfg Config) (*Announcer, error) {
	if cfg.DeviceID == "" || cfg.Name == "" {
		return nil, errors.New("mdns: DeviceID and Name are required")
	}
	text := []string{
		"id=" + cfg.DeviceID,
		"nm=" + cfg.Name,
		"key=" + base64.RawURLEncoding.EncodeToString(cfg.PublicKey),
	}
	server, err := zeroconf.Register(cfg.Name, ServiceType, Domain, cfg.Port, text, cfg.Ifaces)
	if err != nil {
		return nil, fmt.Errorf("mdns: register: %w", err)
	}
	return &Announcer{server: server}, nil
}

// Close stops advertising.
func (a *Announcer) Close() {
	if a.server != nil {
		a.server.Shutdown()
	}
}

// Discoverer finds nearby devices.
type Discoverer struct {
	ifaces []net.Interface
}

// NewDiscoverer returns a Discoverer. A nil ifaces slice selects all interfaces.
func NewDiscoverer(ifaces []net.Interface) *Discoverer {
	return &Discoverer{ifaces: ifaces}
}

// Run starts browsing and returns a channel of discovered peers. Each device is
// emitted once. The channel closes when ctx is canceled.
func (d *Discoverer) Run(ctx context.Context) (<-chan Peer, error) {
	opts := []zeroconf.ClientOption{zeroconf.SelectIPTraffic(zeroconf.IPv4)}
	if len(d.ifaces) > 0 {
		opts = append(opts, zeroconf.SelectIfaces(d.ifaces))
	}
	resolver, err := zeroconf.NewResolver(opts...)
	if err != nil {
		return nil, fmt.Errorf("mdns: resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	if err := resolver.Browse(ctx, ServiceType, Domain, entries); err != nil {
		return nil, fmt.Errorf("mdns: browse: %w", err)
	}

	peers := make(chan Peer)
	go func() {
		defer close(peers)
		seen := make(map[string]struct{})
		for entry := range entries {
			p, ok := peerFromEntry(entry)
			if !ok {
				continue
			}
			if _, dup := seen[p.DeviceID]; dup {
				continue
			}
			seen[p.DeviceID] = struct{}{}
			select {
			case peers <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	return peers, nil
}

// peerFromEntry converts a zeroconf ServiceEntry into a Peer.
func peerFromEntry(e *zeroconf.ServiceEntry) (Peer, bool) {
	if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
		return Peer{}, false
	}
	host := ""
	if len(e.AddrIPv4) > 0 {
		host = e.AddrIPv4[0].String()
	} else {
		host = e.AddrIPv6[0].String()
	}
	txt := parseTXT(e.Text)
	p := Peer{
		DeviceID:  txt["id"],
		Name:      txt["nm"],
		Host:      host,
		Port:      e.Port,
		PublicKey: decodeKey(txt["key"]),
	}
	if p.DeviceID == "" {
		return Peer{}, false
	}
	return p, true
}

// parseTXT converts zeroconf TXT records ("k=v") into a map.
func parseTXT(records []string) map[string]string {
	m := make(map[string]string, len(records))
	for _, r := range records {
		k, v, ok := strings.Cut(r, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

// decodeKey decodes a base64url public key, ignoring malformed values.
func decodeKey(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
