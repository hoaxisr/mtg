package mtglib_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/logger"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var webClientIP = net.IPv4(10, 0, 0, 7)

// fakeDCNetwork ignores the requested address and connects to an in-process
// fake datacenter.
type fakeDCNetwork struct {
	addr string
}

func (f *fakeDCNetwork) Dial(_, _ string) (essentials.Conn, error) {
	c, err := net.Dial("tcp", f.addr)
	if err != nil {
		return nil, err
	}

	return essentials.WrapNetConn(c), nil
}

func (f *fakeDCNetwork) DialContext(_ context.Context, network, address string) (essentials.Conn, error) {
	return f.Dial(network, address)
}

func (f *fakeDCNetwork) MakeHTTPClient(func(context.Context, string, string) (essentials.Conn, error)) *http.Client {
	return &http.Client{}
}

func (f *fakeDCNetwork) NativeDialer() *net.Dialer { return &net.Dialer{} }

// startFakeDC accepts direct-DC obfuscated2 connections and echoes bytes.
func startFakeDC(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() }) //nolint: errcheck

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			go func() {
				defer c.Close() //nolint: errcheck

				_, conn, err := obfuscation.Obfuscator{}.ReadHandshake(essentials.WrapNetConn(c))
				if err != nil {
					return
				}

				io.Copy(conn, conn) //nolint: errcheck
			}()
		}
	}()

	return l.Addr().String()
}

// webPipeConn is a test-local stand-in for a TLS-terminated connection.
type webPipeConn struct {
	net.Conn
}

func (webPipeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: webClientIP, Port: 4242} }
func (c webPipeConn) CloseRead() error   { return c.Close() }
func (c webPipeConn) CloseWrite() error  { return c.Close() }

type webRecorder struct {
	mu     sync.Mutex
	events []mtglib.Event
}

func (r *webRecorder) Send(_ context.Context, evt mtglib.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, evt)
}

func (r *webRecorder) snapshot() []mtglib.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]mtglib.Event(nil), r.events...)
}

func eventsOf[T mtglib.Event](r *webRecorder) []T {
	var out []T

	for _, e := range r.snapshot() {
		if v, ok := e.(T); ok {
			out = append(out, v)
		}
	}

	return out
}

func waitFor[T mtglib.Event](t *testing.T, r *webRecorder) T {
	t.Helper()

	require.Eventually(t, func() bool { return len(eventsOf[T](r)) > 0 },
		5*time.Second, 5*time.Millisecond)

	return eventsOf[T](r)[0]
}

type ipSet struct{ ip net.IP }

func (s ipSet) Contains(ip net.IP) bool { return s.ip.Equal(ip) }
func (ipSet) Run(time.Duration)         {}
func (ipSet) Shutdown()                 {}

type webProxyOpts struct {
	secrets     int
	concurrency uint
	blocklist   mtglib.IPBlocklist
	allowlist   mtglib.IPBlocklist
	replay      mtglib.AntiReplayCache
}

func newWebProxy(t *testing.T, o webProxyOpts) (*mtglib.Proxy, *webRecorder, []mtglib.Secret) {
	t.Helper()

	if o.secrets == 0 {
		o.secrets = 1
	}

	if o.blocklist == nil {
		o.blocklist = ipblocklist.NewNoop()
	}

	if o.allowlist == nil {
		o.allowlist = allowAll{}
	}

	if o.replay == nil {
		o.replay = antireplay.NewNoop()
	}

	secrets := make([]mtglib.Secret, o.secrets)
	for i := range secrets {
		secrets[i] = mtglib.GenerateSecret("example.com")
	}

	rec := &webRecorder{}

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secrets:         secrets,
		Network:         &fakeDCNetwork{addr: startFakeDC(t)},
		AntiReplayCache: o.replay,
		IPBlocklist:     o.blocklist,
		IPAllowlist:     o.allowlist,
		EventStream:     rec,
		Logger:          logger.NewNoopLogger(),
		Concurrency:     o.concurrency,
	})
	require.NoError(t, err)

	t.Cleanup(proxy.Shutdown)

	return proxy, rec, secrets
}

func newWebPipe(t *testing.T) (proxySide essentials.Conn, clientSide essentials.Conn) {
	t.Helper()

	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() }) //nolint: errcheck

	return webPipeConn{a}, essentials.WrapNetConn(b)
}

func rawHandshake(t *testing.T, key []byte, dc int) []byte {
	t.Helper()

	a, b := net.Pipe()
	defer a.Close() //nolint: errcheck
	defer b.Close() //nolint: errcheck

	frame := make([]byte, 64)
	done := make(chan error, 1)

	go func() {
		_, err := io.ReadFull(b, frame)
		done <- err
	}()

	_, err := obfuscation.Obfuscator{Secret: key}.SendHandshake(essentials.WrapNetConn(a), dc)
	require.NoError(t, err)
	require.NoError(t, <-done)

	return frame
}

func TestServeWebConnRoundTrip(t *testing.T) {
	proxy, rec, secrets := newWebProxy(t, webProxyOpts{})
	proxySide, clientSide := newWebPipe(t)

	require.NoError(t, proxy.ServeWebConn(proxySide, 0))

	client, err := obfuscation.Obfuscator{Secret: secrets[0].Key[:]}.SendHandshake(clientSide, 2)
	require.NoError(t, err)

	_, err = client.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 5)
	_, err = io.ReadFull(client, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf))

	assert.True(t, webClientIP.Equal(waitFor[mtglib.EventStart](t, rec).RemoteIP))
	assert.Equal(t, 0, waitFor[mtglib.EventClientMatched](t, rec).SecretIdx)
	waitFor[mtglib.EventTraffic](t, rec)

	client.Close() //nolint: errcheck
	waitFor[mtglib.EventFinish](t, rec)
}

func TestServeWebConnPicksSecretByIndex(t *testing.T) {
	proxy, rec, secrets := newWebProxy(t, webProxyOpts{secrets: 3})

	frame := rawHandshake(t, secrets[2].Key[:], 2)

	// Right index: relays (EventConnectedToDC proves the handshake passed).
	proxySide, clientSide := newWebPipe(t)
	require.NoError(t, proxy.ServeWebConn(proxySide, 2))

	_, err := clientSide.Write(frame)
	require.NoError(t, err)
	assert.Equal(t, 2, waitFor[mtglib.EventClientMatched](t, rec).SecretIdx)
	waitFor[mtglib.EventConnectedToDC](t, rec)

	// Wrong index: same bytes, the conn is closed and nothing is matched.
	wrongSide, wrongClient := newWebPipe(t)
	require.NoError(t, proxy.ServeWebConn(wrongSide, 1))

	_, err = wrongClient.Write(frame)
	require.NoError(t, err)

	_, err = wrongClient.Read(make([]byte, 1))
	assert.Error(t, err)
	assert.Len(t, eventsOf[mtglib.EventClientMatched](rec), 1)
}

func TestServeWebConnRejects(t *testing.T) {
	t.Run("secret index", func(t *testing.T) {
		proxy, _, _ := newWebProxy(t, webProxyOpts{})
		proxySide, _ := newWebPipe(t)

		assert.ErrorIs(t, proxy.ServeWebConn(proxySide, 5), mtglib.ErrSecretIndex)
		assert.ErrorIs(t, proxy.ServeWebConn(proxySide, -1), mtglib.ErrSecretIndex)
	})

	t.Run("remote addr", func(t *testing.T) {
		proxy, _, _ := newWebProxy(t, webProxyOpts{})

		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() }) //nolint: errcheck

		// net.Pipe addresses are not *net.TCPAddr.
		assert.ErrorIs(t, proxy.ServeWebConn(essentials.WrapNetConn(a), 0), mtglib.ErrRemoteAddr)

		_, err := b.Read(make([]byte, 1))
		assert.Error(t, err, "the connection is closed")
	})

	t.Run("blocklist", func(t *testing.T) {
		proxy, rec, _ := newWebProxy(t, webProxyOpts{blocklist: ipSet{webClientIP}})
		proxySide, clientSide := newWebPipe(t)

		assert.ErrorIs(t, proxy.ServeWebConn(proxySide, 0), mtglib.ErrIPBlocklisted)
		assert.Len(t, eventsOf[mtglib.EventIPBlocklisted](rec), 1)

		_, err := clientSide.Read(make([]byte, 1))
		assert.Error(t, err)
	})

	t.Run("allowlist", func(t *testing.T) {
		proxy, rec, _ := newWebProxy(t, webProxyOpts{allowlist: ipSet{net.IPv4(1, 1, 1, 1)}})
		proxySide, _ := newWebPipe(t)

		assert.ErrorIs(t, proxy.ServeWebConn(proxySide, 0), mtglib.ErrIPNotAllowlisted)
		assert.Len(t, eventsOf[mtglib.EventIPBlocklisted](rec), 1)
	})

	t.Run("concurrency", func(t *testing.T) {
		proxy, rec, _ := newWebProxy(t, webProxyOpts{concurrency: 1})

		busySide, _ := newWebPipe(t)
		require.NoError(t, proxy.ServeWebConn(busySide, 0))
		waitFor[mtglib.EventStart](t, rec)

		proxySide, clientSide := newWebPipe(t)
		assert.ErrorIs(t, proxy.ServeWebConn(proxySide, 0), mtglib.ErrConcurrencyLimited)
		assert.Len(t, eventsOf[mtglib.EventConcurrencyLimited](rec), 1)

		_, err := clientSide.Read(make([]byte, 1))
		assert.Error(t, err)
	})

	t.Run("closed", func(t *testing.T) {
		proxy, _, _ := newWebProxy(t, webProxyOpts{})
		proxy.Shutdown()

		proxySide, clientSide := newWebPipe(t)
		assert.ErrorIs(t, proxy.ServeWebConn(proxySide, 0), mtglib.ErrProxyClosed)

		_, err := clientSide.Read(make([]byte, 1))
		assert.Error(t, err)
	})
}

func TestServeWebConnReplay(t *testing.T) {
	cache := antireplay.NewStableBloomFilter(
		antireplay.DefaultStableBloomFilterMaxSize,
		antireplay.DefaultStableBloomFilterErrorRate)
	proxy, rec, secrets := newWebProxy(t, webProxyOpts{replay: cache})

	frame := rawHandshake(t, secrets[0].Key[:], 2)

	first, firstClient := newWebPipe(t)
	require.NoError(t, proxy.ServeWebConn(first, 0))
	_, err := firstClient.Write(frame)
	require.NoError(t, err)
	waitFor[mtglib.EventClientMatched](t, rec)
	assert.Empty(t, eventsOf[mtglib.EventReplayAttack](rec))

	second, secondClient := newWebPipe(t)
	require.NoError(t, proxy.ServeWebConn(second, 0))
	_, err = secondClient.Write(frame)
	require.NoError(t, err)

	waitFor[mtglib.EventReplayAttack](t, rec)
	assert.Len(t, eventsOf[mtglib.EventClientMatched](rec), 1)

	_, err = secondClient.Read(make([]byte, 1))
	assert.Error(t, err)
}

func TestServeWebConnShutdownRace(t *testing.T) {
	for range 20 {
		proxy, rec, _ := newWebProxy(t, webProxyOpts{concurrency: 8})

		const n = 32

		var wg sync.WaitGroup

		for range n {
			wg.Add(1)

			go func() {
				defer wg.Done()

				proxySide, clientSide := newWebPipe(t)
				if err := proxy.ServeWebConn(proxySide, 0); err != nil {
					// Rejected: the conn must have been closed.
					_, rerr := clientSide.Read(make([]byte, 1))
					assert.Error(t, rerr)
				}
			}()
		}

		proxy.Shutdown()
		wg.Wait()
		// Calls that raced past Shutdown's Wait are rejected, never queued.
		proxy.Shutdown()

		assert.Equal(t,
			len(eventsOf[mtglib.EventStart](rec)),
			len(eventsOf[mtglib.EventFinish](rec)))
	}
}
