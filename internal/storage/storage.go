// Package storage provides SQLite-backed persistence (modernc.org/sqlite) for
// the trust store, clipboard history, and blob files.
package storage

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Peer is a trusted peer record.
type Peer struct {
	DeviceID  string
	Name      string
	PublicKey ed25519.PublicKey
}

// Store is a SQLite-backed persistent store.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies
// migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS peers (
    device_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    public_key BLOB NOT NULL,
    paired_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS clipboard_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    text       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("storage: migrate: %w", err)
	}
	return nil
}

// AddPeer inserts or updates a trusted peer.
func (s *Store) AddPeer(deviceID, name string, pub ed25519.PublicKey) error {
	_, err := s.db.Exec(`
INSERT INTO peers (device_id, name, public_key) VALUES (?, ?, ?)
ON CONFLICT(device_id) DO UPDATE SET name = excluded.name, public_key = excluded.public_key`,
		deviceID, name, []byte(pub))
	if err != nil {
		return fmt.Errorf("storage: add peer: %w", err)
	}
	return nil
}

// RemovePeer deletes a trusted peer by device ID.
func (s *Store) RemovePeer(deviceID string) error {
	if _, err := s.db.Exec(`DELETE FROM peers WHERE device_id = ?`, deviceID); err != nil {
		return fmt.Errorf("storage: remove peer: %w", err)
	}
	return nil
}

// Trusted reports whether pub is a trusted peer's public key.
func (s *Store) Trusted(pub ed25519.PublicKey) bool {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM peers WHERE public_key = ?`, []byte(pub)).Scan(&one)
	return err == nil
}

// Peers returns all trusted peers.
func (s *Store) Peers() ([]Peer, error) {
	rows, err := s.db.Query(`SELECT device_id, name, public_key FROM peers ORDER BY paired_at`)
	if err != nil {
		return nil, fmt.Errorf("storage: query peers: %w", err)
	}
	defer rows.Close()

	var peers []Peer
	for rows.Next() {
		var p Peer
		var key []byte
		if err := rows.Scan(&p.DeviceID, &p.Name, &key); err != nil {
			return nil, fmt.Errorf("storage: scan peer: %w", err)
		}
		p.PublicKey = ed25519.PublicKey(key)
		peers = append(peers, p)
	}
	return peers, rows.Err()
}
