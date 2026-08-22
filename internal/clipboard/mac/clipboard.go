//go:build darwin

// Package mac provides the macOS clipboard adapter backed by the pbpaste and
// pbcopy command-line tools.
package mac

import (
	"os/exec"
	"strings"
)

// Clipboard reads and writes the macOS pasteboard via pbpaste/pbcopy.
type Clipboard struct{}

// ReadText returns the current pasteboard text.
func (Clipboard) ReadText() (string, error) {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// WriteText sets the pasteboard text.
func (Clipboard) WriteText(text string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}
