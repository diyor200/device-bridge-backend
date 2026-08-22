package files

import (
	"context"
	"fmt"
	"io"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/protocol"
)

// DefaultChunkSize is the number of bytes read per chunk.
const DefaultChunkSize = 64 * 1024

// Meta describes a received file.
type Meta struct {
	TransferID uint64
	Name       string
	Size       int64
}

// Session drives one side of a file transfer over a control channel and a
// dedicated binary data stream. Control messages (offer/accept/start/complete)
// travel on ctrl; file bytes travel on data as binary chunks.
type Session struct {
	ctrl      *protocol.ControlChannel
	data      io.ReadWriter
	chunkSize int
}

// NewSession returns a transfer session using ctrl for control messages and
// data for binary chunks.
func NewSession(ctrl io.ReadWriter, data io.ReadWriter) *Session {
	return &Session{
		ctrl:      protocol.NewControlChannel(ctrl, protocol.JSONCodec{}),
		data:      data,
		chunkSize: DefaultChunkSize,
	}
}

// SendFile streams a single file to the peer: offer, wait for accept, start,
// chunks, complete. It returns the number of bytes sent.
func (s *Session) SendFile(ctx context.Context, transferID uint64, name string, size int64, r io.Reader) (int64, error) {
	if err := s.send(protocol.TypeFileOffer, protocol.FileOffer{TransferID: transferID, Name: name, Size: size}); err != nil {
		return 0, err
	}
	if err := s.expectTransfer(protocol.TypeFileAccept, transferID); err != nil {
		return 0, err
	}
	if err := s.send(protocol.TypeFileStart, protocol.FileStart{TransferID: transferID}); err != nil {
		return 0, err
	}

	var sent int64
	buf := make([]byte, s.chunkSize)
	for {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		n, err := r.Read(buf)
		if n > 0 {
			if err := EncodeChunk(s.data, Chunk{TransferID: transferID, Offset: sent, Data: buf[:n]}); err != nil {
				return sent, err
			}
			sent += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return sent, err
		}
	}

	if err := s.send(protocol.TypeFileComplete, protocol.FileComplete{TransferID: transferID}); err != nil {
		return sent, err
	}
	return sent, nil
}

// ReceiveFile receives a single file: it handles the offer, accepts, and writes
// chunks to w until size bytes have arrived. It returns the file metadata and
// the number of bytes written.
func (s *Session) ReceiveFile(ctx context.Context, w io.Writer) (Meta, int64, error) {
	offer, err := s.receiveOffer()
	if err != nil {
		return Meta{}, 0, err
	}
	if err := s.send(protocol.TypeFileAccept, protocol.FileAccept{TransferID: offer.TransferID}); err != nil {
		return Meta{}, 0, err
	}
	if err := s.expectTransfer(protocol.TypeFileStart, offer.TransferID); err != nil {
		return Meta{}, 0, err
	}

	var written int64
	for written < offer.Size {
		if err := ctx.Err(); err != nil {
			return Meta{}, written, err
		}
		c, err := DecodeChunk(s.data)
		if err != nil {
			return Meta{}, written, err
		}
		if c.TransferID != offer.TransferID {
			return Meta{}, written, fmt.Errorf("files: unexpected transfer id %d, want %d", c.TransferID, offer.TransferID)
		}
		if _, err := w.Write(c.Data); err != nil {
			return Meta{}, written, err
		}
		written += int64(len(c.Data))
	}

	if err := s.expectTransfer(protocol.TypeFileComplete, offer.TransferID); err != nil {
		return Meta{}, written, err
	}
	return Meta{TransferID: offer.TransferID, Name: offer.Name, Size: offer.Size}, written, nil
}

func (s *Session) send(t protocol.MessageType, payload any) error {
	m, err := protocol.NewMessage(t, payload)
	if err != nil {
		return err
	}
	return s.ctrl.Send(m)
}

func (s *Session) receiveOffer() (protocol.FileOffer, error) {
	m, err := s.ctrl.Receive()
	if err != nil {
		return protocol.FileOffer{}, err
	}
	if m.Type != protocol.TypeFileOffer {
		return protocol.FileOffer{}, fmt.Errorf("files: expected FILE_OFFER, got %q", m.Type)
	}
	var offer protocol.FileOffer
	if err := m.DecodePayload(&offer); err != nil {
		return protocol.FileOffer{}, err
	}
	return offer, nil
}

// expectTransfer reads the next control message, verifies its type and that it
// refers to the expected transfer.
func (s *Session) expectTransfer(t protocol.MessageType, transferID uint64) error {
	m, err := s.ctrl.Receive()
	if err != nil {
		return err
	}
	if m.Type != t {
		return fmt.Errorf("files: expected %q, got %q", t, m.Type)
	}
	var p struct {
		TransferID uint64 `json:"transfer_id"`
	}
	if err := m.DecodePayload(&p); err != nil {
		return err
	}
	if p.TransferID != transferID {
		return fmt.Errorf("files: transfer id mismatch: got %d, want %d", p.TransferID, transferID)
	}
	return nil
}
