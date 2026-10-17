package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCarrier(t *testing.T, mutate func(*Limits)) (*httpsCarrier, *sessionHarness) {
	t.Helper()

	limits := DefaultLimits()
	if mutate != nil {
		mutate(&limits)
	}

	h := newTestSession(t, mutate)

	return newHTTPSCarrier(limits, DefaultTimeouts()), h
}

func upRequest(seq string, contentType string, body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/up", bytes.NewReader(body))
	if seq != "" {
		r.Header.Set("X-Up-Seq", seq)
	}

	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}

	return r
}

func downRequest(cursor string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(http.MethodPost, "/api/v1/down", nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, "/api/v1/down", bytes.NewReader(body))
	}

	r.Header.Set("X-Down-Cursor", cursor)

	return r
}

func TestHTTPSCarrierMode(t *testing.T) {
	c := newHTTPSCarrier(DefaultLimits(), DefaultTimeouts())

	var _ carrier = c

	assert.Equal(t, "https", c.mode())

	h := newTestSession(t, nil)
	rec := httptest.NewRecorder()
	c.handleWS(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ws", nil), h.s)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestHandleUpOK(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	var up, down uint64

	c.onBytes = func(u, d uint64) { up += u; down += d }

	body := batch(openFrame(7), dataFrame(7, []byte("abc")))
	rec := httptest.NewRecorder()
	c.handleUp(rec, upRequest("1", "application/octet-stream", body), h.s)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("X-Up-Ack"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.EqualValues(t, len(body), up)
	assert.Zero(t, down)

	conn := h.serve.conn(t, 0)
	assert.Equal(t, "abc", string(readN(t, conn, 3)))
}

func TestHandleUpRejections(t *testing.T) {
	ok := openFrame(7)

	tests := []struct {
		name string
		req  func() *http.Request
	}{
		{"missing seq", func() *http.Request { return upRequest("", "application/octet-stream", ok) }},
		{"leading zero seq", func() *http.Request { return upRequest("01", "application/octet-stream", ok) }},
		{"signed seq", func() *http.Request { return upRequest("+1", "application/octet-stream", ok) }},
		{"wrong content type", func() *http.Request { return upRequest("1", "text/plain", ok) }},
		{"content type with params", func() *http.Request {
			return upRequest("1", "application/octet-stream; charset=binary", ok)
		}},
		{"missing content type", func() *http.Request { return upRequest("1", "", ok) }},
		{"empty body", func() *http.Request { return upRequest("1", "application/octet-stream", nil) }},
		{"oversized body", func() *http.Request {
			return upRequest("1", "application/octet-stream", make([]byte, DefaultLimits().MaxBodyBytes+1))
		}},
		{"garbage batch", func() *http.Request { return upRequest("1", "application/octet-stream", []byte{1, 2}) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, h := newTestCarrier(t, nil)
			c.onBytes = func(_, _ uint64) { t.Error("onBytes must not be called") }

			rec := httptest.NewRecorder()
			c.handleUp(rec, tt.req(), h.s)

			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Empty(t, rec.Header().Get("X-Up-Ack"))
			assert.Zero(t, rec.Body.Len())
		})
	}
}

func TestHandleUp503OnBackpressure(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	rec := httptest.NewRecorder()
	c.handleUp(rec, upRequest("1", "application/octet-stream", openFrame(7)), h.s)
	require.Equal(t, http.StatusNoContent, rec.Code)

	h.sink.setRefuse(pendingUplink, true)

	body := dataFrame(7, []byte("abc"))
	rec = httptest.NewRecorder()
	c.handleUp(rec, upRequest("2", "application/octet-stream", body), h.s)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.False(t, isClosed(h.s))

	h.sink.setRefuse(pendingUplink, false)

	rec = httptest.NewRecorder()
	c.handleUp(rec, upRequest("2", "application/octet-stream", body), h.s)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "2", rec.Header().Get("X-Up-Ack"))
}

func TestHandleUpProtocolErrorIs404(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	rec := httptest.NewRecorder()
	c.handleUp(rec, upRequest("5", "application/octet-stream", openFrame(7)), h.s)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.True(t, isClosed(h.s))

	rec = httptest.NewRecorder()
	c.handleUp(rec, upRequest("1", "application/octet-stream", openFrame(7)), h.s)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleDownBatch(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	var up, down uint64

	c.onBytes = func(u, d uint64) { up += u; down += d }

	require.True(t, h.s.queueDownlink(Frame{Type: FrameData, StreamID: 7, Payload: []byte("hello")}, pendingDownlink))

	rec := httptest.NewRecorder()
	c.handleDown(rec, downRequest("0", nil), h.s)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, "1", rec.Header().Get("X-Down-Cursor"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	want := dataFrame(7, []byte("hello"))
	assert.Equal(t, strconv.Itoa(len(want)), rec.Header().Get("Content-Length"))
	assert.Equal(t, want, rec.Body.Bytes())
	assert.Zero(t, up)
	assert.EqualValues(t, len(want), down)
}

func TestHandleDownEmpty(t *testing.T) {
	limits := DefaultLimits()
	timeouts := DefaultTimeouts()
	timeouts.LongPoll = 10 * time.Millisecond
	c := newHTTPSCarrier(limits, timeouts)
	h := newTestSession(t, nil)

	rec := httptest.NewRecorder()
	c.handleDown(rec, downRequest("0", nil), h.s)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "0", rec.Header().Get("X-Down-Cursor"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Zero(t, rec.Body.Len())
}

func TestHandleDownRejectsBody(t *testing.T) {
	tests := []struct {
		name string
		req  func() *http.Request
	}{
		{"body", func() *http.Request { return downRequest("0", []byte{1}) }},
		{"content type", func() *http.Request {
			r := downRequest("0", nil)
			r.Header.Set("Content-Type", "application/octet-stream")

			return r
		}},
		{"missing cursor", func() *http.Request {
			r := downRequest("0", nil)
			r.Header.Del("X-Down-Cursor")

			return r
		}},
		{"non-canonical cursor", func() *http.Request { return downRequest("00", nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, h := newTestCarrier(t, nil)

			rec := httptest.NewRecorder()
			c.handleDown(rec, tt.req(), h.s)

			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Zero(t, rec.Body.Len())
		})
	}
}

func TestHandleDownBadCursorIs404(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	rec := httptest.NewRecorder()
	c.handleDown(rec, downRequest("5", nil), h.s)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.True(t, isClosed(h.s))
}

// writeSpy records whether a handler touched the response at all.
type writeSpy struct {
	header  http.Header
	touched bool
}

func (w *writeSpy) Header() http.Header {
	return w.header
}

func (w *writeSpy) Write(p []byte) (int, error) {
	w.touched = true

	return len(p), nil
}

func (w *writeSpy) WriteHeader(int) {
	w.touched = true
}

func TestHandleDownClientGone(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req := downRequest("0", nil).WithContext(ctx)
	spy := &writeSpy{header: http.Header{}}
	done := make(chan struct{})

	go func() {
		defer close(done)
		c.handleDown(spy, req, h.s)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("handler did not return after the client went away")
	}

	assert.False(t, spy.touched)
	assert.Empty(t, spy.header)
	assert.False(t, isClosed(h.s))

	// the next poll with the same cursor still works
	require.True(t, h.s.queueDownlink(Frame{Type: FrameData, StreamID: 7, Payload: []byte("x")}, pendingDownlink))

	rec := httptest.NewRecorder()
	c.handleDown(rec, downRequest("0", nil), h.s)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("X-Down-Cursor"))
	assert.Equal(t, dataFrame(7, []byte("x")), rec.Body.Bytes())

	// and a lost response is replayed verbatim
	rec2 := httptest.NewRecorder()
	c.handleDown(rec2, downRequest("0", nil), h.s)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, rec.Body.Bytes(), rec2.Body.Bytes())
	assert.Equal(t, "1", rec2.Header().Get("X-Down-Cursor"))
}

// deadlineRecorder is a ResponseRecorder that http.ResponseController can
// set read deadlines on; it records them, and fails them with err.
type deadlineRecorder struct {
	*httptest.ResponseRecorder

	err       error
	deadlines []time.Time
}

func newDeadlineRecorder(err error) *deadlineRecorder {
	return &deadlineRecorder{ResponseRecorder: httptest.NewRecorder(), err: err}
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)

	return d.err
}

// assertBodyDeadline checks that a body read was bracketed by an armed
// bodyReadTimeout deadline and its reset.
func assertBodyDeadline(t *testing.T, rec *deadlineRecorder, armedAt time.Time) {
	t.Helper()

	require.Len(t, rec.deadlines, 2)
	assert.WithinDuration(t, armedAt.Add(bodyReadTimeout), rec.deadlines[0], time.Second)
	assert.True(t, rec.deadlines[1].IsZero())
}

func TestBodyReadTimeout(t *testing.T) {
	assert.Equal(t, 30*time.Second, bodyReadTimeout)
}

func TestHandleUpSetsBodyDeadline(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	rec := newDeadlineRecorder(nil)
	started := time.Now()
	c.handleUp(rec, upRequest("1", octetStream, batch(openFrame(7), dataFrame(7, []byte("abc")))), h.s)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("X-Up-Ack"))
	assertBodyDeadline(t, rec, started)

	conn := h.serve.conn(t, 0)
	assert.Equal(t, "abc", string(readN(t, conn, 3)))
}

func TestHandleUpDeadlineFailureIs404(t *testing.T) {
	c, h := newTestCarrier(t, nil)
	c.onBytes = func(_, _ uint64) { t.Error("onBytes must not be called") }

	rec := newDeadlineRecorder(errors.New("connection is gone"))
	c.handleUp(rec, upRequest("1", octetStream, batch(openFrame(7))), h.s)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Len(t, rec.deadlines, 1)
	assert.Zero(t, h.serve.count())

	// The batch was not applied: the same sequence is still the next one.
	c.onBytes = nil
	rec2 := httptest.NewRecorder()
	c.handleUp(rec2, upRequest("1", octetStream, batch(openFrame(7))), h.s)
	assert.Equal(t, http.StatusNoContent, rec2.Code)
}

func TestHandleDownChunkedBodySetsDeadline(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	// A body of unknown length is read (one byte) under the deadline.
	r := downRequest("0", []byte{})
	r.ContentLength = -1
	r.Body = io.NopCloser(bytes.NewReader(nil))

	rec := newDeadlineRecorder(nil)
	started := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	c.handleDown(rec, r.WithContext(ctx), h.s)
	assertBodyDeadline(t, rec, started)

	// No deadline for an empty body: there is nothing to read.
	rec = newDeadlineRecorder(errors.New("must not be called"))
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()

	c.handleDown(rec, downRequest("0", nil).WithContext(ctx2), h.s)
	assert.Empty(t, rec.deadlines)
}

func TestHandleUpConcurrentIs503BeforeBodyIsRead(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	pr, pw := io.Pipe()
	slow := upRequest("1", octetStream, nil)
	slow.Body = pr
	slow.ContentLength = -1

	slowRec := httptest.NewRecorder()
	slowDone := make(chan struct{})

	go func() {
		defer close(slowDone)

		c.handleUp(slowRec, slow, h.s)
	}()

	// Wait until the slow upload holds the slot (its body is still open).
	require.Eventually(t, func() bool {
		h.s.mu.Lock()
		defer h.s.mu.Unlock()

		return h.s.upBusy
	}, 2*time.Second, time.Millisecond)

	rec := httptest.NewRecorder()
	c.handleUp(rec, upRequest("2", octetStream, batch(openFrame(8))), h.s)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "0", rec.Header().Get("Content-Length"))

	select {
	case <-slowDone:
		t.Fatal("the slow upload finished before its body was fed")
	default:
	}

	_, err := pw.Write(batch(openFrame(7)))
	require.NoError(t, err)
	require.NoError(t, pw.Close())
	<-slowDone

	assert.Equal(t, http.StatusNoContent, slowRec.Code)
	assert.Equal(t, "1", slowRec.Header().Get("X-Up-Ack"))

	rec = httptest.NewRecorder()
	c.handleUp(rec, upRequest("2", octetStream, batch(openFrame(8))), h.s)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "2", rec.Header().Get("X-Up-Ack"))
}

func TestHandleUpFailedBodyReleasesSlot(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	pr, pw := io.Pipe()
	r := upRequest("1", octetStream, nil)
	r.Body = pr
	r.ContentLength = -1

	go func() {
		body := batch(openFrame(7))
		_, _ = pw.Write(body[:len(body)/2])
		pw.CloseWithError(errors.New("client went away"))
	}()

	rec := httptest.NewRecorder()
	c.handleUp(rec, r, h.s)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.False(t, isClosed(h.s))

	rec = httptest.NewRecorder()
	c.handleUp(rec, upRequest("1", octetStream, batch(openFrame(7))), h.s)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHandleUpClosedSessionIs404(t *testing.T) {
	c, h := newTestCarrier(t, nil)
	h.s.close()

	rec := httptest.NewRecorder()
	c.handleUp(rec, upRequest("1", octetStream, batch(openFrame(7))), h.s)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// zeroReader returns no bytes and err on every read.
type zeroReader struct{ err error }

func (z zeroReader) Read([]byte) (int, error) { return 0, z.err }

func TestEmptyBodyRequiresEOF(t *testing.T) {
	assert.True(t, emptyBody(nil))
	assert.True(t, emptyBody(http.NoBody))
	assert.True(t, emptyBody(zeroReader{io.EOF}))
	assert.True(t, emptyBody(bytes.NewReader(nil)))
	assert.False(t, emptyBody(zeroReader{errors.New("reset")}))
	assert.False(t, emptyBody(zeroReader{io.ErrUnexpectedEOF}))
	assert.False(t, emptyBody(bytes.NewReader([]byte{0})))
}

func TestHandleDownBodyReadErrorIs404(t *testing.T) {
	c, h := newTestCarrier(t, nil)

	r := downRequest("0", []byte{})
	r.ContentLength = -1
	r.Body = io.NopCloser(zeroReader{errors.New("reset")})

	rec := httptest.NewRecorder()
	c.handleDown(rec, r, h.s)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.False(t, isClosed(h.s))
}

func downBusy(s *session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.downBusy
}

// queueLargeBatch queues about 2 MiB of downlink DATA: one full batch.
func queueLargeBatch(t *testing.T, s *session) {
	t.Helper()

	for id := range uint32(2) {
		require.True(t, s.queueDownlink(Frame{
			Type: FrameData, StreamID: id + 1, Payload: bytes.Repeat([]byte{'x'}, 1<<20-64),
		}, pendingDownlink))
	}
}

// stalledDown starts a real server around c.handleDown with tiny socket
// buffers and sends it a /down from a raw client that never reads. It
// returns a channel closed when the handler has returned.
func stalledDown(t *testing.T, c *httpsCarrier, s *session) <-chan struct{} {
	t.Helper()

	done := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)

		c.handleDown(w, r, s)
	}))
	srv.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if tcp, ok := conn.(*net.TCPConn); ok && state == http.StateNew {
			_ = tcp.SetWriteBuffer(4096)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	if tcp, ok := conn.(*net.TCPConn); ok {
		require.NoError(t, tcp.SetReadBuffer(4096))
	}

	_, err = conn.Write([]byte("POST /api/v1/down HTTP/1.1\r\nHost: example.com\r\n" +
		"X-Down-Cursor: 0\r\nContent-Length: 0\r\n\r\n"))
	require.NoError(t, err)

	return done
}

func TestBodyWriteTimeout(t *testing.T) {
	assert.Equal(t, 30*time.Second, bodyWriteTimeout)
	assert.Equal(t, bodyWriteTimeout, newHTTPSCarrier(DefaultLimits(), DefaultTimeouts()).writeTimeout)
}

func TestHandleDownStalledReaderIsBounded(t *testing.T) {
	c, h := newTestCarrier(t, nil)
	c.writeTimeout = 300 * time.Millisecond
	c.onBytes = func(_, _ uint64) { t.Error("a stalled body must not count as delivered") }

	queueLargeBatch(t, h.s)

	start := time.Now()
	done := stalledDown(t, c, h.s)

	// the write is stuck: the slot is held and the handler has not returned
	require.Eventually(t, func() bool { return downBusy(h.s) }, 2*time.Second, time.Millisecond)

	select {
	case <-done:
		t.Fatal("the response was absorbed by socket buffers; the test does not stall")
	case <-time.After(100 * time.Millisecond):
	}

	// A concurrent /down (acking the batch or replaying it) is refused
	// before it can ack: the batch stays charged while it is written.
	bs, _ := h.sink.totals()
	charged := bs[pendingDownlink]
	require.NotZero(t, charged)

	for _, cursor := range []string{"1", "0"} {
		rec := httptest.NewRecorder()
		c.handleDown(rec, downRequest(cursor, nil), h.s)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, cursor)
		assert.Equal(t, "1", rec.Header().Get("Retry-After"), cursor)
		assert.Empty(t, rec.Header().Get("X-Down-Cursor"), cursor)
	}

	bs, _ = h.sink.totals()
	assert.Equal(t, charged, bs[pendingDownlink])

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled write did not hit its deadline")
	}

	assert.GreaterOrEqual(t, time.Since(start), c.writeTimeout)
	assert.False(t, downBusy(h.s))
	assert.False(t, isClosed(h.s))

	// the slot is free again: the lost batch is replayed, then acked
	c.onBytes = nil
	rec := httptest.NewRecorder()
	c.handleDown(rec, downRequest("0", nil), h.s)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("X-Down-Cursor"))
	assert.Len(t, rec.Body.Bytes(), 2*(FrameHeaderSize+1<<20-64))

	c.timeouts.LongPoll = 10 * time.Millisecond
	rec = httptest.NewRecorder()
	c.handleDown(rec, downRequest("1", nil), h.s)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	bs, _ = h.sink.totals()
	assert.Zero(t, bs[pendingDownlink])
}

func TestHandleDownStalledReaderSessionClosed(t *testing.T) {
	c, h := newTestCarrier(t, nil)
	c.writeTimeout = 300 * time.Millisecond

	queueLargeBatch(t, h.s)

	done := stalledDown(t, c, h.s)
	require.Eventually(t, func() bool { return downBusy(h.s) }, 2*time.Second, time.Millisecond)

	h.s.close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled write did not hit its deadline")
	}

	assert.False(t, downBusy(h.s))

	rec := httptest.NewRecorder()
	c.handleDown(rec, downRequest("0", nil), h.s)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// failingWriter fails every body write.
type failingWriter struct {
	*httptest.ResponseRecorder
}

func (f failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset")
}

func TestHandleDownWriteErrorReleasesSlot(t *testing.T) {
	c, h := newTestCarrier(t, nil)
	c.onBytes = func(_, _ uint64) { t.Error("a failed body must not count as delivered") }

	require.True(t, h.s.queueDownlink(Frame{Type: FrameData, StreamID: 7, Payload: []byte("hello")}, pendingDownlink))

	c.handleDown(failingWriter{httptest.NewRecorder()}, downRequest("0", nil), h.s)
	assert.False(t, downBusy(h.s))

	c.onBytes = nil
	rec := httptest.NewRecorder()
	c.handleDown(rec, downRequest("0", nil), h.s)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, dataFrame(7, []byte("hello")), rec.Body.Bytes())
	assert.False(t, downBusy(h.s))
}
