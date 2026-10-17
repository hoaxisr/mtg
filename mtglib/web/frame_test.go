package web_test

import (
	"bytes"
	"testing"

	"github.com/9seconds/mtg/v2/mtglib/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeFrameLayout(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		[]byte{0x02, 0x01, 0x02, 0x03, 0, 0, 0, 2, 'a', 'b'},
		web.EncodeFrame(web.FrameData, 0x010203, []byte("ab")))
}

func TestHelloBytes(t *testing.T) {
	t.Parallel()

	hello := web.EncodeFrame(web.FrameHello, 0, []byte{1})
	assert.Equal(t, []byte{0x10, 0, 0, 0, 0, 0, 0, 1, 1}, hello)
	assert.NoError(t, web.ParseHello(hello))
	assert.Error(t, web.ParseHello(append(bytes.Clone(hello), hello...)))
	assert.Error(t, web.ParseHello(web.EncodeFrame(web.FrameHello, 0, []byte{2})))
}

func TestParseFramesRoundTrip(t *testing.T) {
	t.Parallel()

	var input []byte

	input = web.AppendFrame(input, web.FrameOpen, 1, nil)
	input = web.AppendFrame(input, web.FrameData, 1, []byte("hello"))
	input = web.AppendFrame(input, web.FrameClose, 1, nil)

	frames, err := web.ParseFrames(input, 0)
	require.NoError(t, err)
	require.Len(t, frames, 3)

	assert.Equal(t, web.FrameOpen, frames[0].Type)
	assert.Equal(t, uint32(1), frames[0].StreamID)
	assert.Empty(t, frames[0].Payload)
	assert.Equal(t, web.FrameData, frames[1].Type)
	assert.Equal(t, []byte("hello"), frames[1].Payload)
	assert.Equal(t, web.FrameClose, frames[2].Type)

	assert.Same(t, &input[web.FrameHeaderSize+web.FrameHeaderSize], &frames[1].Payload[0])
}

func TestParseFramesErrors(t *testing.T) {
	t.Parallel()

	tooBig := []byte{0x02, 0, 0, 1, 0, 0x10, 0, 1}
	short := []byte{0x02, 0, 0, 1, 0, 0, 0, 10, 1, 2, 3, 4, 5}

	var many []byte
	for range web.MaxBatchFrames + 1 {
		many = web.AppendFrame(many, web.FrameClose, 1, nil)
	}

	tests := map[string]struct {
		input      []byte
		maxPayload int
		err        error
	}{
		"short header":    {make([]byte, 7), 0, web.ErrFrameIncomplete},
		"payload too big": {tooBig, 0, web.ErrFramePayloadTooLarge},
		"truncated":       {short, 0, web.ErrFrameIncomplete},
		"too many frames": {many, 0, web.ErrFrameBatchTooLarge},
		"empty":           {nil, 0, web.ErrFrameBatchEmpty},
		"custom max":      {web.EncodeFrame(web.FrameData, 1, make([]byte, 101)), 100, web.ErrFramePayloadTooLarge},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := web.ParseFrames(tt.input, tt.maxPayload)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

func TestValidateClientShape(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		typ     web.FrameType
		id      uint32
		payload []byte
		ok      bool
	}{
		"open":           {web.FrameOpen, 1, nil, true},
		"open payload":   {web.FrameOpen, 1, []byte{1}, false},
		"open id 0":      {web.FrameOpen, 0, nil, false},
		"close":          {web.FrameClose, 1, nil, true},
		"close payload":  {web.FrameClose, 1, []byte{1}, false},
		"close id 0":     {web.FrameClose, 0, nil, false},
		"ping":           {web.FramePing, 0, nil, false},
		"bye":            {web.FrameBye, 0, nil, false},
		"data empty":     {web.FrameData, 1, nil, false},
		"data 1 byte":    {web.FrameData, 1, []byte{1}, true},
		"window ok":      {web.FrameWindow, 1, web.WindowPayload(5), true},
		"window zero":    {web.FrameWindow, 1, web.WindowPayload(0), false},
		"window 3 bytes": {web.FrameWindow, 1, []byte{0, 0, 1}, false},
		"pong":           {web.FramePong, 0, make([]byte, 64), true},
		"pong too long":  {web.FramePong, 0, make([]byte, 65), false},
		"hello id 1":     {web.FrameHello, 1, []byte{1}, false},
		"welcome":        {web.FrameWelcome, 0, []byte{1}, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := web.Frame{Type: tt.typ, StreamID: tt.id, Payload: tt.payload}.ValidateClientShape()
			if tt.ok {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, web.ErrFrameShape)
			}
		})
	}
}

func TestWindowPayloadRoundTrip(t *testing.T) {
	t.Parallel()

	n, err := web.WindowAmount(web.WindowPayload(4 << 20))
	require.NoError(t, err)
	assert.Equal(t, uint32(4<<20), n)
}
