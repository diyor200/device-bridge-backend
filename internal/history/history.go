// Package history implements clipboard history: capture, query, and search,
// with local persistence.
package history

import (
	"time"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/storage"
)

// Entry is a clipboard history entry.
type Entry struct {
	ID        int64
	Text      string
	CreatedAt time.Time
}

// Store records and queries clipboard history, enforcing a maximum size and
// deduplicating consecutive identical entries.
type Store struct {
	db  *storage.Store
	max int
}

// New returns a history store using db, keeping at most max entries. A
// non-positive max means no limit.
func New(db *storage.Store, max int) *Store {
	return &Store{db: db, max: max}
}

// Add records text, skipping it if it equals the most recent entry, and prunes
// entries beyond the maximum.
func (s *Store) Add(text string) error {
	latest, err := s.db.HistoryList(1)
	if err != nil {
		return err
	}
	if len(latest) > 0 && latest[0].Text == text {
		return nil // consecutive duplicate
	}
	if _, err := s.db.AddHistory(text, time.Now()); err != nil {
		return err
	}
	if s.max > 0 {
		return s.db.HistoryTrim(s.max)
	}
	return nil
}

// List returns up to limit recent entries, newest first.
func (s *Store) List(limit int) ([]Entry, error) {
	entries, err := s.db.HistoryList(limit)
	if err != nil {
		return nil, err
	}
	return convert(entries), nil
}

// Search returns entries whose text contains query, newest first.
func (s *Store) Search(query string, limit int) ([]Entry, error) {
	entries, err := s.db.HistorySearch(query, limit)
	if err != nil {
		return nil, err
	}
	return convert(entries), nil
}

func convert(entries []storage.HistoryEntry) []Entry {
	out := make([]Entry, len(entries))
	for i, e := range entries {
		out[i] = Entry{ID: e.ID, Text: e.Text, CreatedAt: e.CreatedAt}
	}
	return out
}
