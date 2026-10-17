package web

import (
	"net"

	"github.com/9seconds/mtg/v2/essentials"
)

// streamProxyConn is the proxy-facing end of a virtual stream. The stream
// protocol has no half-close, so CloseRead and CloseWrite close both directions.
type streamProxyConn struct {
	net.Conn

	remote *net.TCPAddr
	local  *net.TCPAddr
}

func (s *streamProxyConn) RemoteAddr() net.Addr { return s.remote }
func (s *streamProxyConn) LocalAddr() net.Addr  { return s.local }
func (s *streamProxyConn) CloseRead() error     { return s.Close() }
func (s *streamProxyConn) CloseWrite() error    { return s.Close() }

// newStreamPair returns the proxy-facing end (handed to Serve) and the
// session-facing end (pumped by the session). Both ends honour deadlines.
func newStreamPair(clientIP net.IP) (proxySide essentials.Conn, sessionSide net.Conn) {
	proxyEnd, sessionEnd := net.Pipe()

	return &streamProxyConn{
		Conn:   proxyEnd,
		remote: &net.TCPAddr{IP: append(net.IP(nil), clientIP...)},
		local:  &net.TCPAddr{IP: net.IPv4zero},
	}, sessionEnd
}
