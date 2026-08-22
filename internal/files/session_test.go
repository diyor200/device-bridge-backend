package files

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
)

func TestChunkRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Chunk{TransferID: 42, Offset: 1024, Data: []byte("hello chunk")}
	if err := EncodeChunk(&buf, want); err != nil {
		t.Fatalf("EncodeChunk: %v", err)
	}
	got, err := DecodeChunk(&buf)
	if err != nil {
		t.Fatalf("DecodeChunk: %v", err)
	}
	if got.TransferID != want.TransferID || got.Offset != want.Offset || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeChunkTooLarge(t *testing.T) {
	var hdr [20]byte
	binary.BigEndian.PutUint32(hdr[16:20], maxChunkSize+1)
	if _, err := DecodeChunk(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("expected error for oversized chunk length")
	}
}

func TestSendReceiveFile(t *testing.T) {
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()
	data1, data2 := net.Pipe()
	defer data1.Close()
	defer data2.Close()

	const name = "test.bin"
	const transferID = uint64(7)
	content := bytes.Repeat([]byte("0123456789abcdef"), 10000) // 160 KiB, spans multiple chunks

	sender := NewSession(ctrl1, data1)
	receiver := NewSession(ctrl2, data2)

	var (
		sent, received   int64
		meta             Meta
		sendErr, recvErr error
	)
	done := make(chan struct{}, 2)
	go func() {
		sent, sendErr = sender.SendFile(context.Background(), transferID, name, int64(len(content)), bytes.NewReader(content))
		done <- struct{}{}
	}()
	var out bytes.Buffer
	go func() {
		meta, received, recvErr = receiver.ReceiveFile(context.Background(), &out)
		done <- struct{}{}
	}()
	<-done
	<-done

	if sendErr != nil {
		t.Fatalf("SendFile: %v", sendErr)
	}
	if recvErr != nil {
		t.Fatalf("ReceiveFile: %v", recvErr)
	}
	if sent != int64(len(content)) {
		t.Fatalf("sent = %d, want %d", sent, len(content))
	}
	if received != int64(len(content)) {
		t.Fatalf("received = %d, want %d", received, len(content))
	}
	if meta.Name != name || meta.TransferID != transferID || meta.Size != int64(len(content)) {
		t.Fatalf("meta = %+v", meta)
	}
	if !bytes.Equal(out.Bytes(), content) {
		t.Fatal("content mismatch")
	}
}
