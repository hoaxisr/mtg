package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

const e2eWait = 5 * time.Second

// dcCloseMarker makes the fake DC hang up instead of echoing.
var dcCloseMarker = []byte("\x00fake-dc-close-me\x00")

// fakeDCNetwork ignores the requested address and connects to an in-process
// fake datacenter.
type fakeDCNetwork struct {
	addr string
}

func (f *fakeDCNetwork) Dial(_, _ string) (essentials.Conn, error) {
	c, err := net.Dial("tcp", f.addr)
	if err != nil {
		return nil, err //nolint: wrapcheck
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

// startFakeDC accepts direct-DC obfuscated2 connections and echoes bytes
// until it sees dcCloseMarker.
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

			go serveFakeDC(c)
		}
	}()

	return l.Addr().String()
}

func serveFakeDC(c net.Conn) {
	defer c.Close() //nolint: errcheck

	_, conn, err := obfuscation.Obfuscator{}.ReadHandshake(essentials.WrapNetConn(c))
	if err != nil {
		return
	}

	buf := make([]byte, 32<<10)

	var tail []byte

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			seen := append(tail, buf[:n]...) //nolint: gocritic
			if bytes.Contains(seen, dcCloseMarker) {
				return
			}

			tail = append([]byte(nil), seen[max(0, len(seen)-len(dcCloseMarker)):]...)

			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}

		if err != nil {
			return
		}
	}
}

type eventRecorder struct {
	mu     sync.Mutex
	events []mtglib.Event
}

func (r *eventRecorder) Send(_ context.Context, evt mtglib.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, evt)
}

func eventsOf[T mtglib.Event](r *eventRecorder) []T {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []T

	for _, e := range r.events {
		if v, ok := e.(T); ok {
			out = append(out, v)
		}
	}

	return out
}

func waitFor[T mtglib.Event](t *testing.T, r *eventRecorder) T {
	t.Helper()

	require.Eventually(t, func() bool { return len(eventsOf[T](r)) > 0 },
		e2eWait, 5*time.Millisecond)

	return eventsOf[T](r)[0]
}

type ipSet struct{ ip net.IP }

func (s ipSet) Contains(ip net.IP) bool { return s.ip.Equal(ip) }
func (ipSet) Run(time.Duration)         {}
func (ipSet) Shutdown()                 {}

type allowAll struct{}

func (allowAll) Contains(net.IP) bool { return true }
func (allowAll) Run(time.Duration)    {}
func (allowAll) Shutdown()            {}

type e2eOpts struct {
	concurrency uint
	blocklist   mtglib.IPBlocklist
	replay      mtglib.AntiReplayCache
}

type e2eEnv struct {
	handler *Handler
	srv     *httptest.Server
	rec     *eventRecorder
	public  *recordingPublic
	secrets []mtglib.Secret
}

// newE2E runs a real Proxy (2 secrets, fake DC) behind a WEB proxy Handler.
func newE2E(t *testing.T, o e2eOpts) *e2eEnv {
	t.Helper()

	if o.blocklist == nil {
		o.blocklist = ipblocklist.NewNoop()
	}

	if o.replay == nil {
		o.replay = antireplay.NewNoop()
	}

	env := &e2eEnv{
		rec:     &eventRecorder{},
		public:  &recordingPublic{},
		secrets: []mtglib.Secret{handlerSecret(1), handlerSecret(100)},
	}

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secrets:         env.secrets,
		Network:         &fakeDCNetwork{addr: startFakeDC(t)},
		AntiReplayCache: o.replay,
		IPBlocklist:     o.blocklist,
		IPAllowlist:     allowAll{},
		EventStream:     env.rec,
		Logger:          logger.NewNoopLogger(),
		Concurrency:     o.concurrency,
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	profiles := make([]Profile, len(env.secrets))
	for i, s := range env.secrets {
		profiles[i] = Profile{Index: i, Secret: s}
	}

	env.handler, err = NewHandler(Options{
		Hostname: testHostname,
		Profiles: profiles,
		Serve:    proxy.ServeWebConn,
		Public:   env.public,
		Timeouts: Timeouts{LongPoll: 2 * time.Second},
	})
	require.NoError(t, err)

	env.srv = httptest.NewServer(env.handler)

	// Runs before proxy.Shutdown (cleanups are LIFO).
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), e2eWait)
		defer cancel()

		assert.NoError(t, env.handler.Shutdown(ctx))
		env.srv.Close()
	})

	return env
}

func (e *e2eEnv) client(t *testing.T, secretIdx int) *bridgeClient {
	t.Helper()

	c := newBridgeClient(t, e.srv.URL, testHostname, testXFF, e.secrets[secretIdx])
	c.connect()
	t.Cleanup(func() { c.close() })

	return c
}

func randomPayload(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return b
}

// roundTrip writes data to a stream and reads the same amount back.
func roundTrip(t *testing.T, s *clientStream, data []byte) []byte {
	t.Helper()

	type result struct {
		buf []byte
		err error
	}

	done := make(chan result, 1)

	go func() {
		buf := make([]byte, len(data))
		_, err := io.ReadFull(s, buf)
		done <- result{buf, err}
	}()

	_, err := s.Write(data)
	require.NoError(t, err)

	select {
	case r := <-done:
		require.NoError(t, r.err)

		return r.buf
	case <-time.After(10 * time.Second):
		t.Fatalf("stream %d: no echo of %d bytes", s.id, len(data))

		return nil
	}
}

// assertEcho checks that a stream echoes data back unchanged.
func assertEcho(t *testing.T, s *clientStream, data []byte) {
	t.Helper()

	assert.True(t, bytes.Equal(data, roundTrip(t, s, data)), "stream %d: echo differs", s.id)
}

func waitServerClose(t *testing.T, s *clientStream) {
	t.Helper()

	select {
	case <-s.serverClosed():
	case <-time.After(e2eWait):
		t.Fatalf("stream %d: no CLOSE from the server", s.id)
	}
}

func TestE2EEchoThroughProxy(t *testing.T) {
	env := newE2E(t, e2eOpts{})
	c := env.client(t, 1)

	s := c.openStream(1)
	data := randomPayload(t, 300<<10)
	assertEcho(t, s, data)

	matched := eventsOf[mtglib.EventClientMatched](env.rec)
	require.Len(t, matched, 1)
	assert.Equal(t, 1, matched[0].SecretIdx)

	require.Eventually(t, func() bool {
		var read, written bool

		for _, e := range eventsOf[mtglib.EventTraffic](env.rec) {
			read = read || e.IsRead
			written = written || !e.IsRead
		}

		return read && written
	}, e2eWait, 5*time.Millisecond, "traffic events in both directions")

	assert.Empty(t, eventsOf[mtglib.EventFinish](env.rec))
	assert.Equal(t, http.StatusNoContent, c.close())
	require.Eventually(t, func() bool { return len(eventsOf[mtglib.EventFinish](env.rec)) == 1 },
		e2eWait, 5*time.Millisecond)
}

func TestE2ETwoStreamsIndependent(t *testing.T) {
	env := newE2E(t, e2eOpts{})
	c := env.client(t, 0)

	s1 := c.openStream(1)
	s2 := c.openStream(2)

	one, two := randomPayload(t, 70<<10), randomPayload(t, 90<<10)
	assertEcho(t, s1, one)
	assertEcho(t, s2, two)

	// The fake DC hangs up on stream 1: the relay closes it.
	_, err := s1.Write(dcCloseMarker)
	require.NoError(t, err)
	waitServerClose(t, s1)

	_, err = s1.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)

	more := randomPayload(t, 50<<10)
	assertEcho(t, s2, more)

	select {
	case <-s2.serverClosed():
		t.Fatal("stream 2 was closed")
	default:
	}
}

func TestE2EReplayedHandshakeIsClosed(t *testing.T) {
	cache := antireplay.NewStableBloomFilter(
		antireplay.DefaultStableBloomFilterMaxSize,
		antireplay.DefaultStableBloomFilterErrorRate)
	env := newE2E(t, e2eOpts{replay: cache})
	c := env.client(t, 0)

	s1 := c.openStream(1)
	first := randomPayload(t, 4<<10)
	assertEcho(t, s1, first)
	assert.Empty(t, eventsOf[mtglib.EventReplayAttack](env.rec))

	handshake := s1.handshakeBytes()
	require.Len(t, handshake, 64)

	s3 := c.openRawStream(3)
	_, err := s3.Write(handshake)
	require.NoError(t, err)

	waitServerClose(t, s3)
	waitFor[mtglib.EventReplayAttack](t, env.rec)
	assert.Len(t, eventsOf[mtglib.EventClientMatched](env.rec), 1)

	again := randomPayload(t, 4<<10)
	assertEcho(t, s1, again)
}

func TestE2EBlocklistedClientGetsCloseNotPublic(t *testing.T) {
	env := newE2E(t, e2eOpts{blocklist: ipSet{net.ParseIP(testXFF)}})
	c := env.client(t, 0) // bridge and session creation succeed

	s := c.openStreamExpectReject(1)
	waitServerClose(t, s)
	assert.True(t, net.ParseIP(testXFF).Equal(waitFor[mtglib.EventIPBlocklisted](t, env.rec).RemoteIP))
	assert.Empty(t, eventsOf[mtglib.EventClientMatched](env.rec))

	assert.Equal(t, http.StatusNoContent, c.close())
	assert.Zero(t, env.public.count(), "the public site saw a WEB proxy request")
}

func TestE2EPoolOverloadGetsClose(t *testing.T) {
	env := newE2E(t, e2eOpts{concurrency: 1})
	c := env.client(t, 0)

	s1 := c.openStream(1)
	data := randomPayload(t, 4<<10)
	assertEcho(t, s1, data)

	s2 := c.openStreamExpectReject(2)
	waitServerClose(t, s2)
	waitFor[mtglib.EventConcurrencyLimited](t, env.rec)

	s1.close()
	waitFor[mtglib.EventFinish](t, env.rec)

	// The worker goes back to the pool after EventFinish: a CLOSE on a fresh
	// id means the pool is still busy, so retry with the next one.
	next := uint32(3)

	require.Eventually(t, func() bool {
		id := next
		next++

		return tryOpenEcho(c, id, data)
	}, e2eWait, 10*time.Millisecond, "no stream was accepted after stream 1 closed")
}

// tryOpenEcho opens a stream and reports whether it echoes data. It makes no
// assertions, so it is safe inside require.Eventually.
func tryOpenEcho(c *bridgeClient, id uint32, data []byte) bool {
	s := c.openRawStream(id)

	conn, err := obfuscation.Obfuscator{Secret: c.secret.Key[:]}.SendHandshake(s.conn, clientDC)
	if err != nil {
		return false
	}

	s.conn = conn
	done := make(chan []byte, 1)

	go func() {
		buf := make([]byte, len(data))
		if _, err := io.ReadFull(s, buf); err != nil {
			buf = nil
		}

		done <- buf
	}()

	if _, err := s.Write(data); err != nil {
		return false
	}

	select {
	case buf := <-done:
		return bytes.Equal(data, buf)
	case <-time.After(e2eWait):
		return false
	}
}
