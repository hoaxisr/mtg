package web_test

import (
	"testing"

	"github.com/9seconds/mtg/v2/mtglib/web"
	"github.com/stretchr/testify/assert"
)

func FuzzParseFrames(f *testing.F) {
	var seed []byte

	seed = web.AppendFrame(seed, web.FrameOpen, 1, nil)
	seed = web.AppendFrame(seed, web.FrameData, 1, []byte("hello"))
	seed = web.AppendFrame(seed, web.FrameClose, 1, nil)

	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0x10, 0, 0, 0, 0, 0, 0, 1, 1})

	f.Fuzz(func(t *testing.T, input []byte) {
		frames, err := web.ParseFrames(input, 0)
		if err != nil {
			return
		}

		var out []byte
		for _, fr := range frames {
			out = web.AppendFrame(out, fr.Type, fr.StreamID, fr.Payload)
		}

		assert.Equal(t, input, out)
	})
}
