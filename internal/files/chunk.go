package files

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxChunkSize caps a single chunk to avoid unbounded allocation from a
// malicious peer.
const maxChunkSize = 16 << 20 // 16 MiB

// Chunk is one binary chunk of a file transfer on the data channel. Offset is
// the byte offset of the chunk within the file, enabling future resume.
type Chunk struct {
	TransferID uint64
	Offset     int64
	Data       []byte
}

// EncodeChunk writes c to w as [transferID:8][offset:8][length:4][data].
func EncodeChunk(w io.Writer, c Chunk) error {
	if len(c.Data) > maxChunkSize {
		return fmt.Errorf("files: chunk of %d bytes exceeds maximum %d", len(c.Data), maxChunkSize)
	}
	var hdr [20]byte
	binary.BigEndian.PutUint64(hdr[0:8], c.TransferID)
	binary.BigEndian.PutUint64(hdr[8:16], uint64(c.Offset))
	binary.BigEndian.PutUint32(hdr[16:20], uint32(len(c.Data)))
	if err := writeFull(w, hdr[:]); err != nil {
		return err
	}
	return writeFull(w, c.Data)
}

// DecodeChunk reads a chunk from r.
func DecodeChunk(r io.Reader) (Chunk, error) {
	var hdr [20]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Chunk{}, err
	}
	c := Chunk{
		TransferID: binary.BigEndian.Uint64(hdr[0:8]),
		Offset:     int64(binary.BigEndian.Uint64(hdr[8:16])),
	}
	n := binary.BigEndian.Uint32(hdr[16:20])
	if n > maxChunkSize {
		return Chunk{}, fmt.Errorf("files: chunk length %d exceeds maximum %d", n, maxChunkSize)
	}
	c.Data = make([]byte, n)
	if _, err := io.ReadFull(r, c.Data); err != nil {
		return Chunk{}, err
	}
	return c, nil
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
