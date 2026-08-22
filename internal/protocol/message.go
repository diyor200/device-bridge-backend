package protocol

import "encoding/json"

// Version is the current protocol version, advertised in HELLO.
const Version = "0.1.0"

// MessageType identifies the kind of control message.
type MessageType string

// Control-channel message types. FILE_CHUNK is intentionally absent: file
// bytes travel on the binary data channel, not as JSON.
const (
	TypeHello            MessageType = "HELLO"
	TypePair             MessageType = "PAIR"
	TypeClipboardUpdate  MessageType = "CLIPBOARD_UPDATE"
	TypeClipboardRequest MessageType = "CLIPBOARD_REQUEST"
	TypeFileOffer        MessageType = "FILE_OFFER"
	TypeFileAccept       MessageType = "FILE_ACCEPT"
	TypeFileStart        MessageType = "FILE_START"
	TypeFileComplete     MessageType = "FILE_COMPLETE"
	TypeFileCancel       MessageType = "FILE_CANCEL"
	TypePing             MessageType = "PING"
	TypePong             MessageType = "PONG"
	TypeMessage          MessageType = "MESSAGE"
)

// Message is the generic control-channel envelope. The payload is kept as raw
// JSON so a receiver can decode it into the type-specific struct after reading
// Type.
type Message struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// NewMessage builds a Message, marshaling payload into the raw JSON field. A nil
// payload (PING, PONG, etc.) yields a message with no payload.
func NewMessage(t MessageType, payload any) (*Message, error) {
	m := &Message{Type: t}
	if payload == nil {
		return m, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	m.Payload = data
	return m, nil
}

// DecodePayload unmarshals the raw payload into v (a pointer to a concrete
// payload struct).
func (m *Message) DecodePayload(v any) error {
	return json.Unmarshal(m.Payload, v)
}

// Hello is the initial handshake message identifying a device.
type Hello struct {
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	PublicKey []byte `json:"public_key"`
	Version   string `json:"version"`
}

// Pair carries identity material during the pairing handshake. Confirm is set
// on the final message of the exchange when both sides approve the trust.
type Pair struct {
	DeviceID    string `json:"device_id"`
	Name        string `json:"name"`
	PublicKey   []byte `json:"public_key"`
	Certificate []byte `json:"certificate"`
	Confirm     bool   `json:"confirm,omitempty"`
}

// ClipboardUpdate carries clipboard text in either direction.
type ClipboardUpdate struct {
	Text string `json:"text"`
}

// ClipboardRequest asks a peer to send its current clipboard content.
type ClipboardRequest struct{}

// Text is a free-form text message exchanged between paired devices.
type Text struct {
	Text string `json:"text"`
}

// FileOffer advertises an outgoing file.
type FileOffer struct {
	TransferID uint64 `json:"transfer_id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Hash       string `json:"hash,omitempty"`
}

// FileAccept approves an offered file.
type FileAccept struct {
	TransferID uint64 `json:"transfer_id"`
}

// FileStart signals the beginning of chunk transmission.
type FileStart struct {
	TransferID uint64 `json:"transfer_id"`
}

// FileComplete marks a successful transfer end.
type FileComplete struct {
	TransferID uint64 `json:"transfer_id"`
}

// FileCancel aborts a transfer.
type FileCancel struct {
	TransferID uint64 `json:"transfer_id"`
}
