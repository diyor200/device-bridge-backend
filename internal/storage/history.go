package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// HistoryEntry is a clipboard history record.
type HistoryEntry struct {
	ID        int64
	Text      string
	CreatedAt time.Time
}

// AddHistory inserts a history entry and returns its ID.
func (s *Store) AddHistory(text string, at time.Time) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO clipboard_history (text, created_at) VALUES (?, ?)`, text, at.Unix())
	if err != nil {
		return 0, fmt.Errorf("storage: add history: %w", err)
	}
	return res.LastInsertId()
}

// HistoryList returns up to limit recent entries, newest first.
func (s *Store) HistoryList(limit int) ([]HistoryEntry, error) {
	rows, err := s.db.Query(`SELECT id, text, created_at FROM clipboard_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list history: %w", err)
	}
	return scanHistory(rows)
}

// HistorySearch returns entries whose text contains query, newest first.
func (s *Store) HistorySearch(query string, limit int) ([]HistoryEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, text, created_at FROM clipboard_history WHERE text LIKE ? ORDER BY id DESC LIMIT ?`,
		"%"+query+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("storage: search history: %w", err)
	}
	return scanHistory(rows)
}

// HistoryGet returns a single entry by ID.
func (s *Store) HistoryGet(id int64) (HistoryEntry, error) {
	var e HistoryEntry
	var secs int64
	err := s.db.QueryRow(`SELECT id, text, created_at FROM clipboard_history WHERE id = ?`, id).
		Scan(&e.ID, &e.Text, &secs)
	if err != nil {
		return HistoryEntry{}, fmt.Errorf("storage: get history: %w", err)
	}
	e.CreatedAt = time.Unix(secs, 0)
	return e, nil
}

// HistoryDelete removes an entry by ID.
func (s *Store) HistoryDelete(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM clipboard_history WHERE id = ?`, id); err != nil {
		return fmt.Errorf("storage: delete history: %w", err)
	}
	return nil
}

// HistoryTrim keeps the newest keep entries, deleting the rest.
func (s *Store) HistoryTrim(keep int) error {
	_, err := s.db.Exec(
		`DELETE FROM clipboard_history WHERE id NOT IN (SELECT id FROM clipboard_history ORDER BY id DESC LIMIT ?)`,
		keep)
	if err != nil {
		return fmt.Errorf("storage: trim history: %w", err)
	}
	return nil
}

func scanHistory(rows *sql.Rows) ([]HistoryEntry, error) {
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		var secs int64
		if err := rows.Scan(&e.ID, &e.Text, &secs); err != nil {
			return nil, fmt.Errorf("storage: scan history: %w", err)
		}
		e.CreatedAt = time.Unix(secs, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
