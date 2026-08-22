package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// maxFrameSize caps the size of a single frame to avoid unbounded allocation
// from a malicious or buggy peer.
const maxFrameSize = 64 << 20 // 64 MiB

// ErrFrameTooLarge is returned when a frame exceeds maxFrameSize.
var ErrFrameTooLarge = errors.New("protocol: frame exceeds maximum size")

// FrameWriter writes length-prefixed frames to an io.Writer.
type FrameWriter struct {
	w io.Writer
}

// NewFrameWriter returns a FrameWriter writing to w.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame writes a 4-byte big-endian length prefix followed by p.
func (fw *FrameWriter) WriteFrame(p []byte) error {
	if len(p) > maxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	if err := writeFull(fw.w, hdr[:]); err != nil {
		return err
	}
	return writeFull(fw.w, p)
}

// FrameReader reads length-prefixed frames from an io.Reader.
type FrameReader struct {
	r io.Reader
}

// NewFrameReader returns a FrameReader reading from r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// ReadFrame reads the length prefix and returns the frame payload.
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(fr.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeFull writes p fully, handling partial writes.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
