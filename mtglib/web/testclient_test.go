package web

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/mtglib/obfuscation"
	"github.com/stretchr/testify/require"
)

const (
	// clientUpBatch caps the body of one uplink request.
	clientUpBatch = 1 << 20
	// clientRetryDelay is the pause before retrying a 503 uplink.
	clientRetryDelay = 20 * time.Millisecond
	// clientDC is the datacenter every stream asks for.
	clientDC = 2
)

var bootstrapRe = regexp.MustCompile(`const BOOTSTRAP = "([A-Za-z0-9_-]{43})";`)

// bridgeClient is a Go implementation of the bridge page: it creates a
// session and multiplexes streams over the /up and /down carrier. It honours
// the server's per-stream send window and grants WINDOW credit back as
// stream data is read.
type bridgeClient struct {
	t        *testing.T
	baseURL  string
	hostname string
	xff      string
	secret   mtglib.Secret
	http     *http.Client
	token    string

	ctx    context.Context //nolint: containedctx
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// mu guards everything below; cond is broadcast on every change.
	mu       sync.Mutex
	cond     *sync.Cond
	outbox   []byte
	streams  map[uint32]*clientStream
	stopping bool

	closeOnce   sync.Once
	closeStatus int
}

// clientStream is one stream: an obfuscated2 client conn (or a raw one)
// whose bytes travel as DATA frames.
type clientStream struct {
	c    *bridgeClient
	id   uint32
	conn essentials.Conn

	// guarded by c.mu
	credit       int64
	inbound      []byte
	handshake    []byte
	remoteClosed bool
	localClosed  bool
	closedCh     chan struct{}
}

func newBridgeClient(t *testing.T, baseURL, hostname, xff string, profileSecret mtglib.Secret) *bridgeClient {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	c := &bridgeClient{
		t:        t,
		baseURL:  baseURL,
		hostname: hostname,
		xff:      xff,
		secret:   profileSecret,
		http:     &http.Client{Transport: &http.Transport{}},
		ctx:      ctx,
		cancel:   cancel,
		streams:  map[uint32]*clientStream{},
	}
	c.cond = sync.NewCond(&c.mu)

	return c
}

func (c *bridgeClient) request(method, path string, body []byte) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(c.ctx, method, c.baseURL+path, rd)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	req.Host = c.hostname
	req.Header.Set("X-Forwarded-For", c.xff)

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	return req, nil
}

func (c *bridgeClient) do(req *http.Request) (*http.Response, []byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err //nolint: wrapcheck
	}

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)

	return resp, body, err //nolint: wrapcheck
}

// connect fetches the bridge page, creates a session and starts the carrier
// loops.
func (c *bridgeClient) connect() {
	c.t.Helper()

	req, err := c.request(http.MethodGet, "/?bridge="+Capability(c.secret, c.hostname), nil)
	require.NoError(c.t, err)

	resp, page, err := c.do(req)
	require.NoError(c.t, err)
	require.Equal(c.t, http.StatusOK, resp.StatusCode)

	m := bootstrapRe.FindSubmatch(page)
	require.NotNil(c.t, m, "no bootstrap in the bridge page")

	c.token = string(m[1])
	req, err = c.request(http.MethodPost, "/api/v1/session", EncodeFrame(FrameHello, 0, []byte{1}))
	require.NoError(c.t, err)
	req.Header.Set("Content-Type", octetStream)

	resp, body, err := c.do(req)
	require.NoError(c.t, err)
	require.Equal(c.t, http.StatusOK, resp.StatusCode)
	require.Equal(c.t, EncodeFrame(FrameWelcome, 0, nil), body)
	require.Equal(c.t, "0", resp.Header.Get("X-Down-Cursor"))

	c.token = resp.Header.Get("X-Session-Token")
	require.NotEmpty(c.t, c.token)

	c.wg.Add(2) //nolint: mnd

	go c.upLoop()
	go c.downLoop()
}

// openStream opens a stream and performs the client obfuscated2 handshake.
func (c *bridgeClient) openStream(id uint32) *clientStream {
	c.t.Helper()

	s := c.openRawStream(id)

	conn, err := obfuscation.Obfuscator{Secret: c.secret.Key[:]}.SendHandshake(s.conn, clientDC)
	require.NoError(c.t, err)

	s.conn = conn

	return s
}

// openStreamExpectReject opens a stream the server is expected to refuse at
// OPEN: its CLOSE may arrive before the handshake is written, so a closed
// stream is not an error here.
func (c *bridgeClient) openStreamExpectReject(id uint32) *clientStream {
	c.t.Helper()

	s := c.openRawStream(id)

	conn, err := obfuscation.Obfuscator{Secret: c.secret.Key[:]}.SendHandshake(s.conn, clientDC)
	if err != nil {
		require.ErrorIs(c.t, err, net.ErrClosed)
	} else {
		s.conn = conn
	}

	return s
}

// openRawStream opens a stream whose bytes go out as they are written.
func (c *bridgeClient) openRawStream(id uint32) *clientStream {
	s := &clientStream{c: c, id: id, credit: InitialStreamWindow, closedCh: make(chan struct{})}
	s.conn = essentials.WrapNetConn(rawStreamConn{s})

	c.mu.Lock()
	defer c.mu.Unlock()

	c.streams[id] = s
	c.queueLocked(FrameOpen, id, nil)

	return s
}

func (c *bridgeClient) queueLocked(t FrameType, id uint32, payload []byte) {
	c.outbox = AppendFrame(c.outbox, t, id, payload)
	c.cond.Broadcast()
}

// close deletes the session, stops the loops and returns the DELETE status.
func (c *bridgeClient) close() int {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.stopping = true
		c.cond.Broadcast()
		c.mu.Unlock()

		if c.token != "" {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
				c.baseURL+"/api/v1/session", nil)
			if err == nil {
				req.Host = c.hostname
				req.Header.Set("X-Forwarded-For", c.xff)
				req.Header.Set("Authorization", "Bearer "+c.token)

				if resp, _, err := c.do(req); err == nil {
					c.closeStatus = resp.StatusCode
				}
			}
		}

		c.cancel()
		c.wg.Wait()
		c.http.CloseIdleConnections()
	})

	return c.closeStatus
}

// fail reports a carrier failure from a background loop and stops the
// client.
func (c *bridgeClient) fail(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.stopping {
		c.t.Errorf(format, args...)
		c.stopping = true
		c.cond.Broadcast()
	}
}

func (c *bridgeClient) isStopping() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.stopping
}

// takeBatchLocked cuts whole frames, up to clientUpBatch bytes and
// MaxBatchFrames frames, off the outbox.
func (c *bridgeClient) takeBatchLocked() []byte {
	size, frames := 0, 0

	for size < len(c.outbox) && frames < MaxBatchFrames {
		frameSize := FrameHeaderSize + int(binary.BigEndian.Uint32(c.outbox[size+4:size+FrameHeaderSize]))
		if size > 0 && size+frameSize > clientUpBatch {
			break
		}

		size += frameSize
		frames++
	}

	batch := c.outbox[:size:size]
	c.outbox = c.outbox[size:]

	return batch
}

func (c *bridgeClient) upLoop() {
	defer c.wg.Done()

	var seq uint64

	for {
		c.mu.Lock()

		for len(c.outbox) == 0 && !c.stopping {
			c.cond.Wait()
		}

		if c.stopping {
			c.mu.Unlock()

			return
		}

		batch := c.takeBatchLocked()
		c.mu.Unlock()

		seq++
		if !c.sendUp(seq, batch) {
			return
		}
	}
}

// sendUp posts one batch, retrying it on 503.
func (c *bridgeClient) sendUp(seq uint64, batch []byte) bool {
	for {
		req, err := c.request(http.MethodPost, "/api/v1/up", batch)
		if err != nil {
			c.fail("up %d: %v", seq, err)

			return false
		}

		req.Header.Set("Content-Type", octetStream)
		req.Header.Set("X-Up-Seq", strconv.FormatUint(seq, 10))

		resp, _, err := c.do(req)

		switch {
		case c.isStopping():
			return false
		case err != nil:
			c.fail("up %d: %v", seq, err)

			return false
		case resp.StatusCode == http.StatusServiceUnavailable:
			time.Sleep(clientRetryDelay)
		case resp.StatusCode != http.StatusNoContent:
			c.fail("up %d: status %d", seq, resp.StatusCode)

			return false
		case resp.Header.Get("X-Up-Ack") != strconv.FormatUint(seq, 10):
			c.fail("up %d: ack %q", seq, resp.Header.Get("X-Up-Ack"))

			return false
		default:
			return true
		}
	}
}

func (c *bridgeClient) downLoop() {
	defer c.wg.Done()

	cursor := "0"

	for {
		req, err := c.request(http.MethodPost, "/api/v1/down", nil)
		if err != nil {
			c.fail("down %s: %v", cursor, err)

			return
		}

		req.Header.Set("X-Down-Cursor", cursor)

		resp, body, err := c.do(req)

		switch {
		case c.isStopping():
			return
		case err != nil:
			c.fail("down %s: %v", cursor, err)

			return
		case resp.StatusCode == http.StatusNoContent:
		case resp.StatusCode != http.StatusOK:
			c.fail("down %s: status %d", cursor, resp.StatusCode)

			return
		default:
			frames, err := ParseFrames(body, 0)
			if err != nil {
				c.fail("down %s: %v", cursor, err)

				return
			}

			c.dispatch(frames)
		}

		cursor = resp.Header.Get("X-Down-Cursor")
	}
}

func (c *bridgeClient) dispatch(frames []Frame) {
	c.mu.Lock()
	defer c.mu.Unlock()

	defer c.cond.Broadcast()

	for _, f := range frames {
		s := c.streams[f.StreamID]

		switch f.Type { //nolint: exhaustive
		case FramePing:
			c.queueLocked(FramePong, 0, f.Payload)
		case FrameData:
			if s != nil && !s.localClosed {
				s.inbound = append(s.inbound, f.Payload...)
			}
		case FrameWindow:
			if n, err := WindowAmount(f.Payload); err == nil && s != nil {
				s.credit += int64(n)
			}
		case FrameClose:
			if s != nil && !s.remoteClosed {
				s.remoteClosed = true
				close(s.closedCh)
			}
		default:
			c.t.Errorf("unexpected downlink frame type 0x%02x", byte(f.Type))
		}
	}
}

func (s *clientStream) Read(p []byte) (int, error) { return s.conn.Read(p) } //nolint: wrapcheck
// Write encrypts a copy: the obfuscated2 conn encrypts in place.
func (s *clientStream) Write(p []byte) (int, error) {
	return s.conn.Write(append([]byte(nil), p...)) //nolint: wrapcheck
}

// serverClosed is closed once the server sent CLOSE for this stream.
func (s *clientStream) serverClosed() <-chan struct{} { return s.closedCh }

// handshakeBytes returns the first 64 bytes written to the stream.
func (s *clientStream) handshakeBytes() []byte {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()

	return append([]byte(nil), s.handshake...)
}

// close sends CLOSE for the stream.
func (s *clientStream) close() {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()

	if !s.localClosed {
		s.localClosed = true
		s.c.queueLocked(FrameClose, s.id, nil)
	}
}

func (s *clientStream) writeRaw(p []byte) (int, error) {
	c := s.c

	c.mu.Lock()
	defer c.mu.Unlock()

	if missing := obfuscatedHandshakeSize - len(s.handshake); missing > 0 {
		s.handshake = append(s.handshake, p[:min(missing, len(p))]...)
	}

	written := 0

	for written < len(p) {
		for s.credit <= 0 && !s.remoteClosed && !s.localClosed && !c.stopping {
			c.cond.Wait()
		}

		if s.remoteClosed || s.localClosed || c.stopping {
			return written, net.ErrClosed
		}

		n := min(int64(len(p)-written), DataChunk, s.credit)
		c.queueLocked(FrameData, s.id, p[written:written+int(n)])
		s.credit -= n
		written += int(n)
	}

	return written, nil
}

func (s *clientStream) readRaw(p []byte) (int, error) {
	c := s.c

	c.mu.Lock()
	defer c.mu.Unlock()

	for len(s.inbound) == 0 {
		switch {
		case s.remoteClosed:
			return 0, io.EOF
		case s.localClosed || c.stopping:
			return 0, net.ErrClosed
		}

		c.cond.Wait()
	}

	n := copy(p, s.inbound)
	s.inbound = s.inbound[n:]

	if !s.localClosed && !s.remoteClosed {
		c.queueLocked(FrameWindow, s.id, WindowPayload(uint32(n))) //nolint: gosec
	}

	return n, nil
}

const obfuscatedHandshakeSize = 64

var errNoDeadlines = errors.New("deadlines are not supported")

// rawStreamConn is the net.Conn face of a clientStream's DATA plumbing.
type rawStreamConn struct {
	s *clientStream
}

func (r rawStreamConn) Read(p []byte) (int, error)  { return r.s.readRaw(p) }
func (r rawStreamConn) Write(p []byte) (int, error) { return r.s.writeRaw(p) }
func (r rawStreamConn) Close() error {
	r.s.close()

	return nil
}
func (rawStreamConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (rawStreamConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (rawStreamConn) SetDeadline(time.Time) error      { return errNoDeadlines }
func (rawStreamConn) SetReadDeadline(time.Time) error  { return errNoDeadlines }
func (rawStreamConn) SetWriteDeadline(time.Time) error { return errNoDeadlines }
