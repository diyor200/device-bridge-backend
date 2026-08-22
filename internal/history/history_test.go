package history

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/storage"
)

func newStore(t *testing.T, max int) (*Store, *storage.Store) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db, max), db
}

func TestAddAndList(t *testing.T) {
	h, _ := newStore(t, 0)
	for _, text := range []string{"first", "second", "third"} {
		if err := h.Add(text); err != nil {
			t.Fatalf("Add(%q): %v", text, err)
		}
	}
	entries, err := h.List(10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	if entries[0].Text != "third" || entries[1].Text != "second" || entries[2].Text != "first" {
		t.Fatalf("order wrong: %v", texts(entries))
	}
}

func TestDedupConsecutive(t *testing.T) {
	h, _ := newStore(t, 0)
	for i := 0; i < 3; i++ {
		if err := h.Add("same"); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	entries, _ := h.List(10)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 after dedup", len(entries))
	}
}

func TestCap(t *testing.T) {
	h, _ := newStore(t, 3)
	for i := 0; i < 10; i++ {
		if err := h.Add("entry-" + strconv.Itoa(i)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	entries, _ := h.List(100)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3 after cap", len(entries))
	}
	// The newest three survive.
	if entries[0].Text != "entry-9" || entries[1].Text != "entry-8" || entries[2].Text != "entry-7" {
		t.Fatalf("unexpected survivors: %v", texts(entries))
	}
}

func TestSearch(t *testing.T) {
	h, _ := newStore(t, 0)
	for _, text := range []string{"hello world", "goodbye", "hello again"} {
		if err := h.Add(text); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	entries, err := h.Search("hello", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("search results = %d, want 2", len(entries))
	}
}

func texts(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Text
	}
	return out
}
