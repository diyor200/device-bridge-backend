package clipboard

import (
	"context"
	"testing"
	"time"
)

func TestMemoryClipboard(t *testing.T) {
	m := NewMemory("hello")
	if got, _ := m.ReadText(); got != "hello" {
		t.Fatalf("ReadText = %q, want hello", got)
	}
	if err := m.WriteText("world"); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if got, _ := m.ReadText(); got != "world" {
		t.Fatalf("ReadText = %q, want world", got)
	}
}

func TestWatcherDetectsChange(t *testing.T) {
	m := NewMemory("hello")
	w := NewWatcher(m, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := w.Changes(ctx)

	select {
	case got := <-ch:
		t.Fatalf("unexpected initial emission %q", got)
	case <-time.After(30 * time.Millisecond):
	}

	if err := m.WriteText("world"); err != nil {
		t.Fatalf("WriteText: %v", err)
	}

	select {
	case got := <-ch:
		if got != "world" {
			t.Fatalf("change = %q, want world", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for change")
	}
}

func TestWatcherStopsOnCancel(t *testing.T) {
	m := NewMemory("x")
	w := NewWatcher(m, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	ch := w.Changes(ctx)
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed after cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed after cancel")
	}
}
