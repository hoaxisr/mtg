package web

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ essentials.Conn = (*streamProxyConn)(nil)

func TestStreamPairRemoteAddrIsTCPAddr(t *testing.T) {
	ip := net.ParseIP("10.1.2.3")
	proxySide, sessionSide := newStreamPair(ip)
	defer func() { _ = proxySide.Close() }()
	defer func() { _ = sessionSide.Close() }()

	addr, ok := proxySide.RemoteAddr().(*net.TCPAddr)
	require.True(t, ok)
	assert.True(t, ip.Equal(addr.IP))

	ip[len(ip)-1] = 99
	assert.False(t, ip.Equal(addr.IP))

	local, ok := proxySide.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)
	assert.True(t, net.IPv4zero.Equal(local.IP))
}

func TestStreamPairBytesFlow(t *testing.T) {
	proxySide, sessionSide := newStreamPair(net.IPv4(1, 2, 3, 4))
	defer func() { _ = proxySide.Close() }()
	defer func() { _ = sessionSide.Close() }()

	go sessionSide.Write([]byte("ping")) //nolint: errcheck
	buf := make([]byte, 4)
	_, err := io.ReadFull(proxySide, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))

	go proxySide.Write([]byte("pong")) //nolint: errcheck
	_, err = io.ReadFull(sessionSide, buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf))
}

func TestStreamPairCloseReadClosesBoth(t *testing.T) {
	for name, closeFn := range map[string]func(essentials.Conn) error{
		"read":  essentials.Conn.CloseRead,
		"write": essentials.Conn.CloseWrite,
	} {
		t.Run(name, func(t *testing.T) {
			proxySide, sessionSide := newStreamPair(net.IPv4(1, 2, 3, 4))
			defer func() { _ = sessionSide.Close() }()

			require.NoError(t, closeFn(proxySide))
			_, err := sessionSide.Write([]byte("x"))
			assert.ErrorIs(t, err, io.ErrClosedPipe)
		})
	}
}

func TestStreamPairDeadline(t *testing.T) {
	proxySide, sessionSide := newStreamPair(net.IPv4(1, 2, 3, 4))
	defer func() { _ = proxySide.Close() }()
	defer func() { _ = sessionSide.Close() }()

	require.NoError(t, proxySide.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
	_, err := proxySide.Read(make([]byte, 1))
	var ne net.Error
	require.True(t, errors.As(err, &ne))
	assert.True(t, ne.Timeout())
}
