package protocol

import "encoding/json"

// Codec serializes control-channel messages. JSON is the MVP codec; a
// MessagePack implementation can be added later without touching the protocol
// or transport layers.
type Codec interface {
	Marshal(*Message) ([]byte, error)
	Unmarshal([]byte) (*Message, error)
}

// JSONCodec is the default control-channel codec.
type JSONCodec struct{}

// Marshal encodes m as JSON.
func (JSONCodec) Marshal(m *Message) ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal decodes a JSON-encoded Message.
func (JSONCodec) Unmarshal(data []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
