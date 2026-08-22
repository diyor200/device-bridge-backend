// Package device models peers and the session/connection manager that ties a
// paired peer to an active encrypted connection.
package device

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/identity"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/pairing"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/protocol"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/storage"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/transport"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/transport/tcp"
)

// Peer identifies a remote device for pairing or messaging.
type Peer struct {
	DeviceID  string
	Name      string
	Addr      string
	PublicKey ed25519.PublicKey
}

// Config configures a Node.
type Config struct {
	DataDir    string // identity + trust store location
	Name       string // human-readable device name
	ListenAddr string // TCP listen address, e.g. "127.0.0.1:0"
}

// Node is a running bridge instance on this device: it owns the identity, the
// trust store, the encrypted listener, and dials peers for pairing and
// messaging.
type Node struct {
	cfg   Config
	id    *identity.Identity
	store *storage.Store

	listenTr transport.Transport // accepts any self-signed cert; trust at app layer
	dialTr   transport.Transport // pins trusted + pending keys
	ln       transport.Listener

	// PairHandler is consulted for incoming pairing requests; returning true
	// accepts and persists the peer.
	PairHandler func(pairing.Info) bool
	// MessageHandler receives incoming text messages.
	MessageHandler func(fromDeviceID, text string)

	mu      sync.Mutex
	pending map[string]ed25519.PublicKey
	conns   map[transport.Connection]struct{}

	wg sync.WaitGroup
}

// New loads or creates the identity and trust store and prepares the node. Call
// Start to begin accepting connections.
func New(cfg Config) (*Node, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("device: DataDir is required")
	}
	if cfg.Name == "" {
		return nil, errors.New("device: Name is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}

	id, err := identity.LoadOrCreate(filepath.Join(cfg.DataDir, "identity"))
	if err != nil {
		return nil, err
	}
	store, err := storage.Open(filepath.Join(cfg.DataDir, "bridge.db"))
	if err != nil {
		return nil, err
	}

	n := &Node{
		cfg:     cfg,
		id:      id,
		store:   store,
		pending: make(map[string]ed25519.PublicKey),
		conns:   make(map[transport.Connection]struct{}),
	}

	n.listenTr, err = tcp.New(tcp.Config{Identity: id, Trust: nil})
	if err != nil {
		store.Close()
		return nil, err
	}
	n.dialTr, err = tcp.New(tcp.Config{Identity: id, Trust: n})
	if err != nil {
		store.Close()
		return nil, err
	}
	return n, nil
}

// DeviceID returns this node's device ID.
func (n *Node) DeviceID() string { return string(n.id.DeviceID()) }

// Name returns this node's display name.
func (n *Node) Name() string { return n.cfg.Name }

// PublicKey returns this node's public key.
func (n *Node) PublicKey() ed25519.PublicKey { return n.id.PublicKey() }

// Trusted implements transport.TrustStore: a key is accepted if it is a trusted
// peer or pending pairing.
func (n *Node) Trusted(pub ed25519.PublicKey) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.store.Trusted(pub) {
		return true
	}
	for _, k := range n.pending {
		if k.Equal(pub) {
			return true
		}
	}
	return false
}

// Start begins accepting encrypted connections.
func (n *Node) Start() error {
	ln, err := n.listenTr.Listen(n.cfg.ListenAddr)
	if err != nil {
		return err
	}
	n.ln = ln
	n.wg.Add(1)
	go n.acceptLoop()
	return nil
}

// ListenAddr returns the node's bound address, or "" if not started.
func (n *Node) ListenAddr() string {
	if n.ln == nil {
		return ""
	}
	return n.ln.Addr().String()
}

// Close stops the listener, closes active connections, and closes the store.
func (n *Node) Close() error {
	if n.ln != nil {
		n.ln.Close()
	}
	n.mu.Lock()
	for c := range n.conns {
		c.Close()
	}
	n.conns = map[transport.Connection]struct{}{}
	n.mu.Unlock()
	n.wg.Wait()
	return n.store.Close()
}

// Pair initiates pairing with peer (whose address and public key come from
// discovery), pinning the peer's key, exchanging identities, and persisting
// trust on confirmation.
func (n *Node) Pair(ctx context.Context, peer Peer) error {
	n.mu.Lock()
	n.pending[peer.DeviceID] = peer.PublicKey
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pending, peer.DeviceID)
		n.mu.Unlock()
	}()

	conn, err := n.dialTr.Connect(ctx, transport.Peer{DeviceID: peer.DeviceID, Addr: peer.Addr})
	if err != nil {
		return fmt.Errorf("device: dial: %w", err)
	}
	defer conn.Close()

	sess := pairing.NewSession(conn, n.id, n.store)
	info, err := sess.Exchange(n.cfg.Name)
	if err != nil {
		return err
	}
	if n.PairHandler != nil && !n.PairHandler(info) {
		return errors.New("device: pairing rejected")
	}
	return sess.Confirm()
}

// SendText sends a text message to a trusted peer (identified by device ID) at
// addr. The peer must already be paired; its key is looked up from the trust
// store during the TLS handshake. It dials a fresh connection per message
// (persistent sessions are a future optimization).
func (n *Node) SendText(ctx context.Context, deviceID, addr, text string) error {
	conn, err := n.dialTr.Connect(ctx, transport.Peer{DeviceID: deviceID, Addr: addr})
	if err != nil {
		return fmt.Errorf("device: dial: %w", err)
	}
	defer conn.Close()

	ch := protocol.NewControlChannel(conn, protocol.JSONCodec{})
	if err := n.sendHello(ch); err != nil {
		return err
	}
	if err := n.expectHello(ch); err != nil {
		return err
	}
	msg, err := protocol.NewMessage(protocol.TypeMessage, protocol.Text{Text: text})
	if err != nil {
		return err
	}
	return ch.Send(msg)
}

func (n *Node) acceptLoop() {
	defer n.wg.Done()
	for {
		conn, err := n.ln.Accept()
		if err != nil {
			return
		}
		n.wg.Add(1)
		go n.handle(conn)
	}
}

func (n *Node) handle(conn transport.Connection) {
	defer n.wg.Done()

	n.mu.Lock()
	n.conns[conn] = struct{}{}
	n.mu.Unlock()
	defer func() {
		conn.Close()
		n.mu.Lock()
		delete(n.conns, conn)
		n.mu.Unlock()
	}()

	ch := protocol.NewControlChannel(conn, protocol.JSONCodec{})
	trusted := n.store.Trusted(conn.PeerPublicKey())

	msg, err := ch.Receive()
	if err != nil {
		return
	}
	// Untrusted peers may only pair; a trusted peer may send anything.
	if !trusted && msg.Type != protocol.TypePair {
		return
	}

	switch msg.Type {
	case protocol.TypeHello:
		if err := n.sendHello(ch); err != nil {
			return
		}
		n.messageLoop(conn, ch)
	case protocol.TypePair:
		n.handlePair(ch, msg)
	}
}

// messageLoop processes messages from a trusted peer.
func (n *Node) messageLoop(conn transport.Connection, ch *protocol.ControlChannel) {
	for {
		msg, err := ch.Receive()
		if err != nil {
			return
		}
		switch msg.Type {
		case protocol.TypeMessage:
			var t protocol.Text
			if err := msg.DecodePayload(&t); err == nil && n.MessageHandler != nil {
				n.MessageHandler(conn.PeerDeviceID(), t.Text)
			}
		case protocol.TypePing:
			if pong, err := protocol.NewMessage(protocol.TypePong, nil); err == nil {
				ch.Send(pong)
			}
		}
	}
}

// handlePair handles the responder side of pairing: verify the peer's identity,
// confirm, persist, and reply with our identity.
func (n *Node) handlePair(ch *protocol.ControlChannel, msg *protocol.Message) {
	var p protocol.Pair
	if err := msg.DecodePayload(&p); err != nil {
		return
	}
	info, err := pairing.Verify(&p)
	if err != nil {
		return
	}
	if n.PairHandler == nil || !n.PairHandler(info) {
		return
	}
	if err := n.store.AddPeer(info.DeviceID, info.Name, info.PublicKey); err != nil {
		return
	}

	cert, err := n.id.CertificateDER()
	if err != nil {
		return
	}
	resp, err := protocol.NewMessage(protocol.TypePair, protocol.Pair{
		DeviceID:    n.DeviceID(),
		Name:        n.cfg.Name,
		PublicKey:   n.id.PublicKey(),
		Certificate: cert,
		Confirm:     true,
	})
	if err != nil {
		return
	}
	ch.Send(resp)
}

func (n *Node) sendHello(ch *protocol.ControlChannel) error {
	m, err := protocol.NewMessage(protocol.TypeHello, protocol.Hello{
		DeviceID:  n.DeviceID(),
		Name:      n.cfg.Name,
		PublicKey: n.id.PublicKey(),
		Version:   protocol.Version,
	})
	if err != nil {
		return err
	}
	return ch.Send(m)
}

func (n *Node) expectHello(ch *protocol.ControlChannel) error {
	msg, err := ch.Receive()
	if err != nil {
		return err
	}
	if msg.Type != protocol.TypeHello {
		return fmt.Errorf("device: expected HELLO, got %q", msg.Type)
	}
	return nil
}
