package clipboard

import "sync"

// Memory is an in-memory Clipboard implementation, useful for tests and as a
// default when no platform adapter is available.
type Memory struct {
	mu   sync.Mutex
	text string
}

// NewMemory returns a Memory seeded with initial text.
func NewMemory(initial string) *Memory {
	return &Memory{text: initial}
}

// ReadText returns the current text.
func (m *Memory) ReadText() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.text, nil
}

// WriteText sets the text.
func (m *Memory) WriteText(text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.text = text
	return nil
}
