package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const octetStream = "application/octet-stream"

// httpsCarrier carries frames over plain HTTPS requests: one uplink POST per
// batch and a long-polled downlink POST.
type httpsCarrier struct {
	limits   Limits
	timeouts Timeouts
	// writeTimeout bounds writing one downlink body (bodyWriteTimeout).
	writeTimeout time.Duration

	// onBytes, if set, is told about every accepted uplink body and every
	// delivered downlink body.
	onBytes func(up, down uint64)
}

func newHTTPSCarrier(limits Limits, timeouts Timeouts) *httpsCarrier {
	return &httpsCarrier{limits: limits, timeouts: timeouts, writeTimeout: bodyWriteTimeout}
}

func (c *httpsCarrier) mode() string {
	return "https"
}

func (c *httpsCarrier) countBytes(up, down int) {
	if c.onBytes != nil {
		c.onBytes(uint64(up), uint64(down)) //nolint: gosec
	}
}

func (c *httpsCarrier) handleUp(w http.ResponseWriter, r *http.Request, s *session) {
	if ct := r.Header.Values("Content-Type"); len(ct) != 1 || ct[0] != octetStream {
		localNotFound(w)

		return
	}

	seqs := r.Header.Values("X-Up-Seq")
	if len(seqs) != 1 {
		localNotFound(w)

		return
	}

	seq, err := canonicalUint(seqs[0])
	if err != nil {
		localNotFound(w)

		return
	}

	// The uplink slot is taken before the body is read: a session buffers
	// at most one uplink body at a time, and excess uploads are refused
	// before they cost any memory.
	switch err := s.beginUpload(); {
	case errors.Is(err, errConcurrent):
		retryLater(w)

		return
	case err != nil: // errSessionClosed
		localNotFound(w)

		return
	}

	defer s.endUpload()

	if !armBodyDeadline(w) {
		localNotFound(w)

		return
	}

	// MaxBytesError also lands here.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(c.limits.MaxBodyBytes)))

	disarmBodyDeadline(w)

	if err != nil || len(body) == 0 {
		localNotFound(w)

		return
	}

	ack, err := s.processUp(seq, body)

	switch {
	case errors.Is(err, errBackpressure):
		retryLater(w)

		return
	case err != nil: // errSessionProtocol, errSessionClosed
		localNotFound(w)

		return
	}

	c.countBytes(len(body), 0)

	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Up-Ack", strconv.FormatUint(ack, 10))
	w.WriteHeader(http.StatusNoContent)
}

// retryLater answers an uplink that cannot be taken right now.
func retryLater(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Retry-After", "1")
	h.Set("Content-Length", "0")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (c *httpsCarrier) handleDown(w http.ResponseWriter, r *http.Request, s *session) {
	if len(r.Header.Values("Content-Type")) != 0 || r.ContentLength > 0 || !emptyBodyBounded(w, r) {
		localNotFound(w)

		return
	}

	cursors := r.Header.Values("X-Down-Cursor")
	if len(cursors) != 1 {
		localNotFound(w)

		return
	}

	cursor, err := canonicalUint(cursors[0])
	if err != nil {
		localNotFound(w)

		return
	}

	// body is shared with a possible replay: it is written, never modified.
	// A non-empty body comes with the session's downlink write slot: while
	// it is written, another poll is refused (503) before it can ack the
	// batch, so the body stays charged to the budgets until the write ends.
	body, next, err := s.poll(r.Context(), cursor, c.timeouts.LongPoll)

	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return // the client went away; nobody is listening
	case errors.Is(err, errConcurrent):
		retryLater(w)

		return
	case err != nil: // errCursor, errSessionClosed
		localNotFound(w)

		return
	}

	h := w.Header()

	if len(body) == 0 {
		h.Set("Cache-Control", "no-store")
		h.Set("X-Down-Cursor", strconv.FormatUint(next, 10))
		w.WriteHeader(http.StatusNoContent)

		return
	}

	c.writeBody(w, s, body, next)
}

// writeBody writes a non-empty downlink batch and releases the session's
// downlink write slot that poll handed out with it. A reader that stops
// consuming must not hold the slot and the body forever: the write and the
// flush run under a deadline. On any failure the batch stays
// unacknowledged and the client's retry replays it.
func (c *httpsCarrier) writeBody(w http.ResponseWriter, s *session, body []byte, next uint64) {
	defer s.endDownload()

	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		retryLater(w)

		return
	}

	defer rc.SetWriteDeadline(time.Time{}) //nolint: errcheck

	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Down-Cursor", strconv.FormatUint(next, 10))
	h.Set("Content-Type", octetStream)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body); err != nil {
		return
	}

	if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return
	}

	c.countBytes(0, len(body))
}

func (c *httpsCarrier) handleWS(w http.ResponseWriter, _ *http.Request, _ *session) {
	localNotFound(w)
}

// emptyBody reports whether a request body has no bytes at all. Only a
// read that ends with EOF proves it: a zero-byte read failing otherwise
// (a deadline, a reset, a malformed chunked body) is not an empty body.
func emptyBody(body io.Reader) bool {
	if body == nil || body == http.NoBody {
		return true
	}

	var one [1]byte

	n, err := io.ReadFull(body, one[:])

	return n == 0 && errors.Is(err, io.EOF)
}
