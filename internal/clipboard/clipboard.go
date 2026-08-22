// Package clipboard exposes a platform-independent clipboard interface plus a
// watcher that detects changes and publishes them through the bridge protocol.
package clipboard

// Clipboard reads and writes clipboard text. Platform adapters (macOS
// NSPasteboard, Android ClipboardManager) implement this interface. Text-only
// for the MVP; richer types (images, files) can be added later.
type Clipboard interface {
	ReadText() (string, error)
	WriteText(text string) error
}
