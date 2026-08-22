package protocol

import "io"

// ControlChannel ties a Codec to a length-prefixed stream, giving a typed
// Send/Receive interface for control messages over a single io.ReadWriter.
type ControlChannel struct {
	fr    *FrameReader
	fw    *FrameWriter
	codec Codec
}

// NewControlChannel returns a ControlChannel over rw using codec.
func NewControlChannel(rw io.ReadWriter, codec Codec) *ControlChannel {
	return &ControlChannel{
		fr:    NewFrameReader(rw),
		fw:    NewFrameWriter(rw),
		codec: codec,
	}
}

// Send marshals and writes m as a single frame.
func (c *ControlChannel) Send(m *Message) error {
	data, err := c.codec.Marshal(m)
	if err != nil {
		return err
	}
	return c.fw.WriteFrame(data)
}

// Receive reads and unmarshals the next message.
func (c *ControlChannel) Receive() (*Message, error) {
	data, err := c.fr.ReadFrame()
	if err != nil {
		return nil, err
	}
	return c.codec.Unmarshal(data)
}
