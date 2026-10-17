package web

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// FrameHeaderSize is a size of a frame header: type (1), stream id (3)
	// and payload length (4).
	FrameHeaderSize = 8
	// MaxFramePayload is a hard cap of a frame payload.
	MaxFramePayload = 1 << 20
	// InitialStreamWindow is an initial flow control window of a stream.
	InitialStreamWindow = 4 << 20
	// DataChunk is a maximum size of a DATA payload we produce.
	DataChunk = 64 << 10
	// MaxStreamID is a maximal stream id (it is encoded in 3 bytes).
	MaxStreamID = 0xFFFFFF
	// MaxBatchFrames is a maximal number of frames in a single batch.
	MaxBatchFrames = 4096

	maxPingPayload = 64
)

// FrameType is a type of a frame.
type FrameType byte

// Frame types.
const (
	FrameOpen    FrameType = 0x01
	FrameData    FrameType = 0x02
	FrameClose   FrameType = 0x03
	FrameWindow  FrameType = 0x04
	FramePing    FrameType = 0x05
	FramePong    FrameType = 0x06
	FrameHello   FrameType = 0x10
	FrameWelcome FrameType = 0x11
	FrameBye     FrameType = 0x1f
)

// Frame is a single parsed frame. Payload aliases the parsed input.
type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte
}

var (
	ErrFrameIncomplete      = errors.New("incomplete frame")
	ErrFramePayloadTooLarge = errors.New("frame payload is too large")
	ErrFrameBatchTooLarge   = errors.New("too many frames in a batch")
	ErrFrameBatchEmpty      = errors.New("empty batch")
	ErrFrameShape           = errors.New("invalid frame shape")
)

// AppendFrame appends an encoded frame to dst. It panics if streamID
// does not fit into MaxStreamID.
func AppendFrame(dst []byte, t FrameType, streamID uint32, payload []byte) []byte {
	if streamID > MaxStreamID {
		panic(fmt.Sprintf("stream id %d is out of range", streamID))
	}

	dst = append(dst, byte(t), byte(streamID>>16), byte(streamID>>8), byte(streamID))
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(payload))) //nolint: gosec
	dst = append(dst, payload...)

	return dst
}

// EncodeFrame returns a single encoded frame.
func EncodeFrame(t FrameType, streamID uint32, payload []byte) []byte {
	return AppendFrame(make([]byte, 0, FrameHeaderSize+len(payload)), t, streamID, payload)
}

// ParseFrames parses the whole input as a batch of frames. If maxPayload is
// not positive or exceeds MaxFramePayload, MaxFramePayload is used.
func ParseFrames(input []byte, maxPayload int) ([]Frame, error) {
	if maxPayload <= 0 || maxPayload > MaxFramePayload {
		maxPayload = MaxFramePayload
	}

	if len(input) == 0 {
		return nil, ErrFrameBatchEmpty
	}

	var frames []Frame

	for len(input) > 0 {
		if len(frames) >= MaxBatchFrames {
			return nil, ErrFrameBatchTooLarge
		}

		if len(input) < FrameHeaderSize {
			return nil, ErrFrameIncomplete
		}

		length := uint64(binary.BigEndian.Uint32(input[4:FrameHeaderSize]))
		if length > uint64(maxPayload) {
			return nil, ErrFramePayloadTooLarge
		}

		if uint64(len(input)-FrameHeaderSize) < length {
			return nil, ErrFrameIncomplete
		}

		end := FrameHeaderSize + int(length)
		frames = append(frames, Frame{
			Type:     FrameType(input[0]),
			StreamID: uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3]),
			Payload:  input[FrameHeaderSize:end:end],
		})
		input = input[end:]
	}

	return frames, nil
}

// ParseHello checks that input is exactly one HELLO frame of version 1.
func ParseHello(input []byte) error {
	frames, err := ParseFrames(input, maxPingPayload)
	if err != nil {
		return fmt.Errorf("cannot parse hello: %w", err)
	}

	if len(frames) != 1 {
		return fmt.Errorf("%w: hello must be a single frame", ErrFrameShape)
	}

	f := frames[0]
	if f.Type != FrameHello || f.StreamID != 0 || len(f.Payload) != 1 || f.Payload[0] != 1 {
		return fmt.Errorf("%w: unexpected hello", ErrFrameShape)
	}

	return nil
}

// ValidateClientShape checks that a frame is acceptable from a client
// after the handshake.
func (f Frame) ValidateClientShape() error {
	ok := false

	switch f.Type {
	case FrameOpen:
		ok = f.StreamID != 0 && len(f.Payload) == 0
	case FrameData:
		ok = f.StreamID != 0 && len(f.Payload) > 0
	case FrameClose:
		ok = f.StreamID != 0 && len(f.Payload) == 0
	case FrameWindow:
		_, err := WindowAmount(f.Payload)
		ok = f.StreamID != 0 && err == nil
	case FramePong:
		ok = f.StreamID == 0 && len(f.Payload) <= maxPingPayload
	}

	if !ok {
		return fmt.Errorf("%w: type=0x%02x id=%d len=%d", ErrFrameShape, byte(f.Type), f.StreamID, len(f.Payload))
	}

	return nil
}

// WindowPayload encodes a WINDOW payload.
func WindowPayload(n uint32) []byte {
	return binary.BigEndian.AppendUint32(make([]byte, 0, 4), n)
}

// WindowAmount decodes a WINDOW payload. Amount must be positive.
func WindowAmount(p []byte) (uint32, error) {
	if len(p) != 4 {
		return 0, fmt.Errorf("%w: window payload must be 4 bytes", ErrFrameShape)
	}

	n := binary.BigEndian.Uint32(p)
	if n == 0 {
		return 0, fmt.Errorf("%w: window amount is zero", ErrFrameShape)
	}

	return n, nil
}
