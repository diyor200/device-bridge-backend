package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNewMessageWithPayload(t *testing.T) {
	m, err := NewMessage(TypeHello, Hello{DeviceID: "abc", Name: "mac", PublicKey: []byte{1, 2, 3}, Version: Version})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if m.Type != TypeHello {
		t.Fatalf("Type = %q, want %q", m.Type, TypeHello)
	}
	var h Hello
	if err := m.DecodePayload(&h); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if h.DeviceID != "abc" || h.Name != "mac" || h.Version != Version {
		t.Fatalf("decoded payload = %+v", h)
	}
	if !bytes.Equal(h.PublicKey, []byte{1, 2, 3}) {
		t.Fatalf("public key = %v", h.PublicKey)
	}
}

func TestNewMessageNilPayload(t *testing.T) {
	m, err := NewMessage(TypePing, nil)
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if m.Type != TypePing {
		t.Fatalf("Type = %q, want %q", m.Type, TypePing)
	}
	if len(m.Payload) != 0 {
		t.Fatalf("payload = %q, want empty", m.Payload)
	}
}

func TestJSONCodecRoundTrip(t *testing.T) {
	var codec JSONCodec
	in, err := NewMessage(TypeFileOffer, FileOffer{TransferID: 7, Name: "photo.jpg", Size: 1024})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	data, err := codec.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := codec.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Type != in.Type {
		t.Fatalf("Type = %q, want %q", out.Type, in.Type)
	}
	var fo FileOffer
	if err := out.DecodePayload(&fo); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if fo.TransferID != 7 || fo.Name != "photo.jpg" || fo.Size != 1024 {
		t.Fatalf("decoded payload = %+v", fo)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	fr := NewFrameReader(&buf)

	payloads := [][]byte{
		[]byte("hello"),
		{},
		make([]byte, 4096),
	}
	for _, p := range payloads {
		if err := fw.WriteFrame(p); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for _, want := range payloads {
		got, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame = %x, want %x", got, want)
		}
	}
	if _, err := fr.ReadFrame(); err == nil {
		t.Fatal("expected EOF after all frames")
	}
}

func TestFrameLengthPrefix(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	payload := []byte("hi")
	if err := fw.WriteFrame(payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	raw := buf.Bytes()
	if len(raw) != 4+len(payload) {
		t.Fatalf("raw length = %d, want %d", len(raw), 4+len(payload))
	}
	if n := binary.BigEndian.Uint32(raw[:4]); n != uint32(len(payload)) {
		t.Fatalf("prefix = %d, want %d", n, len(payload))
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	big := make([]byte, maxFrameSize+1)
	if err := fw.WriteFrame(big); err != ErrFrameTooLarge {
		t.Fatalf("WriteFrame err = %v, want ErrFrameTooLarge", err)
	}
}

func TestControlChannelRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	ch := NewControlChannel(&buf, JSONCodec{})

	msgs := []*Message{}
	for _, tc := range []struct {
		typ     MessageType
		payload any
	}{
		{TypeHello, Hello{DeviceID: "d1", Name: "mac", PublicKey: []byte{9, 9}, Version: Version}},
		{TypePing, nil},
		{TypeClipboardUpdate, ClipboardUpdate{Text: "copied text"}},
	} {
		m, err := NewMessage(tc.typ, tc.payload)
		if err != nil {
			t.Fatalf("NewMessage: %v", err)
		}
		msgs = append(msgs, m)
	}

	for _, m := range msgs {
		if err := ch.Send(m); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	for _, want := range msgs {
		got, err := ch.Receive()
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if got.Type != want.Type {
			t.Fatalf("Type = %q, want %q", got.Type, want.Type)
		}
	}
}
