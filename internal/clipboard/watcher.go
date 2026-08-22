package clipboard

import (
	"context"
	"time"
)

// DefaultInterval is the polling frequency when none is specified.
const DefaultInterval = 500 * time.Millisecond

// Watcher detects clipboard changes by polling. Polling is used because neither
// macOS nor Android exposes a reliable cross-platform change notification.
type Watcher struct {
	clip     Clipboard
	interval time.Duration
}

// NewWatcher returns a Watcher polling clip. A non-positive interval uses
// DefaultInterval.
func NewWatcher(clip Clipboard, interval time.Duration) *Watcher {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Watcher{clip: clip, interval: interval}
}

// Changes polls the clipboard and sends the new text on the returned channel
// whenever it differs from the last observed value. It does not emit the value
// present at startup. The channel closes when ctx is canceled.
//
// Note: tracking the last value means copying identical text twice in a row is
// observed as a single change. Change-count tracking is a future improvement.
func (w *Watcher) Changes(ctx context.Context) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		last, err := w.clip.ReadText()
		if err != nil {
			last = ""
		}
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				text, err := w.clip.ReadText()
				if err != nil || text == last {
					continue
				}
				last = text
				select {
				case ch <- text:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch
}
