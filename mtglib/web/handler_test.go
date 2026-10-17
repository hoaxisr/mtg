package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHostname = "proxy.example.com"
	testXFF      = "203.0.113.7"
	publicBody   = "public site body\n"
)

type recordedRequest struct {
	method string
	uri    string
	host   string
	header http.Header
	body   []byte
}

// recordingPublic is a decoy that records every request it gets and answers
// with a fixed 200 body.
type recordingPublic struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

func (p *recordingPublic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	p.mu.Lock()
	p.reqs = append(p.reqs, recordedRequest{
		method: r.Method,
		uri:    r.RequestURI,
		host:   r.Host,
		header: r.Header.Clone(),
		body:   body,
	})
	p.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Decoy", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, publicBody)
}

func (p *recordingPublic) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.reqs)
}

func handlerSecret(b byte) mtglib.Secret {
	s := mtglib.Secret{Host: "storage.googleapis.com"}
	for i := range s.Key {
		s.Key[i] = b + byte(i)
	}

	return s
}

func testProfiles() []Profile {
	return []Profile{
		{Index: 0, Secret: handlerSecret(1)},
		{Index: 1, Secret: handlerSecret(100)},
	}
}

type handlerHarness struct {
	h      *Handler
	srv    *httptest.Server
	public *recordingPublic
	serve  *fakeServe
}

func newHandlerHarness(t *testing.T, mutate func(*Options)) *handlerHarness {
	t.Helper()

	hh := &handlerHarness{public: &recordingPublic{}, serve: &fakeServe{}}
	opts := Options{
		Hostname: testHostname,
		Profiles: testProfiles(),
		Serve:    hh.serve.serve,
		Public:   hh.public,
		Timeouts: Timeouts{LongPoll: 5 * time.Second},
	}

	if mutate != nil {
		mutate(&opts)
	}

	h, err := NewHandler(opts)
	require.NoError(t, err)

	hh.h = h
	hh.srv = httptest.NewServer(h)

	t.Cleanup(func() {
		hh.srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_ = h.Shutdown(ctx)
	})

	return hh
}

func newRequest(t *testing.T, base, method, target string, body []byte) *http.Request {
	t.Helper()

	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, base+target, rd)
	require.NoError(t, err)

	req.Host = testHostname
	req.Header.Set("X-Forwarded-For", testXFF)

	return req
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func do(t *testing.T, req *http.Request) response {
	t.Helper()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return response{status: resp.StatusCode, header: resp.Header, body: body}
}

func (hh *handlerHarness) bridge(t *testing.T, profileIdx int) string {
	t.Helper()

	req := newRequest(t, hh.srv.URL, http.MethodGet, "/?bridge="+hh.h.Capability(profileIdx), nil)
	res := do(t, req)
	require.Equal(t, http.StatusOK, res.status)

	m := regexp.MustCompile(`const BOOTSTRAP = "([A-Za-z0-9_-]{43})";`).FindSubmatch(res.body)
	require.NotNil(t, m, "no bootstrap in the bridge page")

	return string(m[1])
}

func (hh *handlerHarness) createReq(t *testing.T, bootstrap string) *http.Request {
	t.Helper()

	req := newRequest(t, hh.srv.URL, http.MethodPost, "/api/v1/session", helloBody())
	req.Header.Set("Authorization", "Bearer "+bootstrap)
	req.Header.Set("Content-Type", octetStream)

	return req
}

func (hh *handlerHarness) session(t *testing.T, profileIdx int) string {
	t.Helper()

	res := do(t, hh.createReq(t, hh.bridge(t, profileIdx)))
	require.Equal(t, http.StatusOK, res.status)

	token := res.header.Get("X-Session-Token")
	require.Len(t, token, tokenEncodedSize)

	return token
}

func (hh *handlerHarness) up(t *testing.T, token, seq string, body []byte) response {
	t.Helper()

	req := newRequest(t, hh.srv.URL, http.MethodPost, "/api/v1/up", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", octetStream)
	req.Header.Set("X-Up-Seq", seq)

	return do(t, req)
}

func (hh *handlerHarness) down(t *testing.T, token, cursor string) response {
	t.Helper()

	req := newRequest(t, hh.srv.URL, http.MethodPost, "/api/v1/down", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Down-Cursor", cursor)

	return do(t, req)
}

func (hh *handlerHarness) deleteSession(t *testing.T, token string) response {
	t.Helper()

	req := newRequest(t, hh.srv.URL, http.MethodDelete, "/api/v1/session", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	return do(t, req)
}

func waitServed(t *testing.T, f *fakeServe, n int) {
	t.Helper()

	require.Eventually(t, func() bool { return f.count() >= n }, 2*time.Second, 5*time.Millisecond)
}

func assertLocal404(t *testing.T, res response) {
	t.Helper()

	assert.Equal(t, http.StatusNotFound, res.status)
	assert.Equal(t, "no-store", res.header.Get("Cache-Control"))
	assert.Empty(t, res.body)
	assert.Empty(t, res.header.Get("X-Decoy"))
}

func TestNewHandlerValidation(t *testing.T) {
	t.Parallel()

	base := func() Options {
		return Options{
			Hostname: testHostname,
			Profiles: testProfiles(),
			Serve:    (&fakeServe{}).serve,
			Public:   &recordingPublic{},
		}
	}

	_, err := NewHandler(base())
	require.NoError(t, err)

	cases := map[string]func(*Options){
		"bad hostname":     func(o *Options) { o.Hostname = "Proxy.Example.com" },
		"empty hostname":   func(o *Options) { o.Hostname = "" },
		"no profiles":      func(o *Options) { o.Profiles = nil },
		"invalid secret":   func(o *Options) { o.Profiles[1].Secret = mtglib.Secret{} },
		"duplicate keys":   func(o *Options) { o.Profiles[1].Secret = o.Profiles[0].Secret },
		"duplicate index":  func(o *Options) { o.Profiles[1].Index = 0 },
		"negative index":   func(o *Options) { o.Profiles[0].Index = -1 },
		"nil serve":        func(o *Options) { o.Serve = nil },
		"nil public":       func(o *Options) { o.Public = nil },
		"short token key":  func(o *Options) { o.TokenKey = make([]byte, 16) },
		"long token key":   func(o *Options) { o.TokenKey = make([]byte, 33) },
		"empty token key":  func(o *Options) { o.TokenKey = []byte{} },
		"bad limits":       func(o *Options) { o.Limits = DefaultLimits(); o.Limits.MaxSessions = -1 },
		"partial limits":   func(o *Options) { o.Limits = Limits{MaxSessions: 1} },
		"negative timeout": func(o *Options) { o.Timeouts.LongPoll = -time.Second },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := base()
			mutate(&opts)

			h, err := NewHandler(opts)
			require.ErrorIs(t, err, ErrOptions)
			assert.Nil(t, h)
		})
	}
}

func TestNewHandlerDefaults(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)

	assert.Equal(t, DefaultLimits(), hh.h.limits)
	assert.Equal(t, 5*time.Second, hh.h.timeouts.LongPoll)
	assert.Equal(t, DefaultTimeouts().ReconnectGrace, hh.h.timeouts.ReconnectGrace)
	assert.Equal(t, DefaultTimeouts().BootstrapLifetime, hh.h.timeouts.BootstrapLifetime)
	assert.Equal(t, DefaultTimeouts().Shutdown, hh.h.timeouts.Shutdown)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}, hh.h.trusted)

	// The derived token key is stable: a second handler accepts tokens of
	// the first.
	token := hh.session(t, 0)

	other, err := NewHandler(Options{
		Hostname: testHostname,
		Profiles: testProfiles(),
		Serve:    (&fakeServe{}).serve,
		Public:   &recordingPublic{},
	})
	require.NoError(t, err)

	_, ok := other.signer.verifyBearer(token, tokenSession)
	assert.True(t, ok)
}

func randomToken(t *testing.T) string {
	t.Helper()

	raw := make([]byte, tokenRawSize)
	_, err := rand.Read(raw)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(raw)
}

func headerLines(h http.Header) []string {
	var lines []string

	for name, values := range h {
		if name == "Date" {
			continue
		}

		for _, v := range values {
			lines = append(lines, name+": "+v)
		}
	}

	slices.Sort(lines)

	return lines
}

func TestStrangerParity(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)
	alone := &recordingPublic{}
	aloneSrv := httptest.NewServer(alone)

	t.Cleanup(aloneSrv.Close)

	type stranger struct {
		method string
		target string
		body   []byte
		setup  func(*http.Request)
	}

	// one random bearer per stranger, identical in both requests
	bearer := func() func(*http.Request) {
		v := "Bearer " + randomToken(t)

		return func(r *http.Request) { r.Header.Set("Authorization", v) }
	}
	upBearer, oversizedBearer, sessionBearer := bearer(), bearer(), bearer()
	strangers := map[string]stranger{
		"root":       {method: http.MethodGet, target: "/"},
		"about":      {method: http.MethodGet, target: "/about.html"},
		"head":       {method: http.MethodHead, target: "/"},
		"options":    {method: http.MethodOptions, target: "/"},
		"cookie":     {method: http.MethodGet, target: "/", setup: func(r *http.Request) { r.Header.Set("Cookie", "a=b") }},
		"other host": {method: http.MethodGet, target: "/", setup: func(r *http.Request) { r.Host = "other.example.org" }},
		"two xff": {method: http.MethodGet, target: "/", setup: func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.1")
		}},
		"bridge random": {method: http.MethodGet, target: "/?bridge=" + randomToken(t)},
		"up random bearer": {
			method: http.MethodPost, target: "/api/v1/up", body: batch(openFrame(1)),
			setup: func(r *http.Request) {
				upBearer(r)
				r.Header.Set("Content-Type", octetStream)
				r.Header.Set("X-Up-Seq", "1")
			},
		},
		"up oversized": {
			method: http.MethodPost, target: "/api/v1/up", body: make([]byte, 3<<20),
			setup: func(r *http.Request) {
				oversizedBearer(r)
				r.Header.Set("Content-Type", octetStream)
			},
		},
		"session random bearer": {
			method: http.MethodPost, target: "/api/v1/session", body: helloBody(),
			setup: func(r *http.Request) {
				sessionBearer(r)
				r.Header.Set("Content-Type", octetStream)
			},
		},
		"delete random bearer": {method: http.MethodDelete, target: "/api/v1/session", setup: bearer()},
	}

	for name, st := range strangers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			send := func(base string) response {
				req := newRequest(t, base, st.method, st.target, st.body)
				if st.setup != nil {
					st.setup(req)
				}

				// identical requests to both servers
				req.Header.Set("X-Request-Name", name)

				return do(t, req)
			}

			got := send(hh.srv.URL)
			want := send(aloneSrv.URL)

			assert.Equal(t, want.status, got.status)
			assert.Equal(t, headerLines(want.header), headerLines(got.header))
			assert.Equal(t, want.body, got.body)
			assert.Equal(t, http.StatusOK, got.status)
			assert.Empty(t, got.header.Get("Cache-Control"))
		})
	}

	// what the decoy saw is the same request in both cases
	byName := func(p *recordingPublic) map[string]recordedRequest {
		p.mu.Lock()
		defer p.mu.Unlock()

		out := map[string]recordedRequest{}
		for _, r := range p.reqs {
			out[r.header.Get("X-Request-Name")] = r
		}

		return out
	}

	t.Cleanup(func() {
		a, b := byName(hh.public), byName(alone)
		assert.Len(t, a, len(strangers))

		for name, ra := range a {
			rb := b[name]
			assert.Equal(t, rb.method, ra.method, name)
			assert.Equal(t, rb.uri, ra.uri, name)
			assert.Equal(t, rb.host, ra.host, name)
			assert.Equal(t, headerLines(rb.header), headerLines(ra.header), name)
			assert.Equal(t, rb.body, ra.body, name)
		}
	})
}

func TestBridgeFlow(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)

	req := newRequest(t, hh.srv.URL, http.MethodGet, "/?bridge="+Capability(testProfiles()[1].Secret, testHostname), nil)
	res := do(t, req)
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, "text/html; charset=utf-8", res.header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.header.Get("Cache-Control"))

	m := regexp.MustCompile(`const BOOTSTRAP = "([A-Za-z0-9_-]{43})";`).FindSubmatch(res.body)
	require.NotNil(t, m)
	assert.Contains(t, string(res.body), "const LONG_POLL_MS = 5000;")
	assert.Contains(t, string(res.body), "const BATCH_LIMIT = 2097152;")

	res = do(t, hh.createReq(t, string(m[1])))
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, "https", res.header.Get("X-Carrier-Mode"))
	assert.Equal(t, "0", res.header.Get("X-Down-Cursor"))
	assert.Equal(t, "no-store", res.header.Get("Cache-Control"))
	assert.Equal(t, EncodeFrame(FrameWelcome, 0, nil), res.body)

	token := res.header.Get("X-Session-Token")
	require.Len(t, token, tokenEncodedSize)

	res = hh.up(t, token, "1", batch(openFrame(1), dataFrame(1, []byte("hello"))))
	require.Equal(t, http.StatusNoContent, res.status)
	assert.Equal(t, "1", res.header.Get("X-Up-Ack"))

	waitServed(t, hh.serve, 1)

	conn := hh.serve.conn(t, 0)
	assert.Equal(t, []byte("hello"), readN(t, conn, 5))
	assert.Equal(t, 1, hh.serve.idx[0])

	res = hh.down(t, token, "0")
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, "1", res.header.Get("X-Down-Cursor"))

	frames, err := ParseFrames(res.body, MaxFramePayload)
	require.NoError(t, err)
	require.NotEmpty(t, frames)
	assert.Equal(t, FrameWindow, frames[0].Type)
	assert.Equal(t, uint32(1), frames[0].StreamID)

	stats := hh.h.Stats()
	assert.Equal(t, 1, stats.SessionsLive)
	assert.Equal(t, uint64(len(helloBody())+len(batch(openFrame(1), dataFrame(1, []byte("hello"))))), stats.BytesUp)
	assert.Equal(t, uint64(len(EncodeFrame(FrameWelcome, 0, nil))+len(res.body)), stats.BytesDown)

	res = hh.deleteSession(t, token)
	assert.Equal(t, http.StatusNoContent, res.status)
	assert.Equal(t, "no-store", res.header.Get("Cache-Control"))

	calls := hh.public.count()

	assertLocal404(t, hh.up(t, token, "2", batch(dataFrame(1, []byte("x")))))
	assert.Equal(t, calls, hh.public.count())
	assert.Equal(t, 0, hh.h.Stats().SessionsLive)
}

func TestBridgeWrongCapabilityIsPublic(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)

	res := do(t, newRequest(t, hh.srv.URL, http.MethodGet, "/?bridge="+randomToken(t), nil))
	assert.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, publicBody, string(res.body))
	assert.Equal(t, "1", res.header.Get("X-Decoy"))
	assert.Equal(t, 1, hh.public.count())
	assert.Equal(t, 0, hh.h.Stats().BootstrapsLive)
}

func TestAuthenticTokenWrongPathIsLocal404(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)
	token := hh.session(t, 0)
	calls := hh.public.count()

	req := newRequest(t, hh.srv.URL, http.MethodGet, "/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	assertLocal404(t, do(t, req))
	assert.Equal(t, calls, hh.public.count())

	// a bridge request with a real capability on a wrong host is local too
	req = newRequest(t, hh.srv.URL, http.MethodGet, "/?bridge="+hh.h.Capability(0), nil)
	req.Host = "other.example.org"

	assertLocal404(t, do(t, req))
	assert.Equal(t, calls, hh.public.count())
}

func TestAuthenticRequestRequiresClientIP(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)

	req := newRequest(t, hh.srv.URL, http.MethodGet, "/?bridge="+hh.h.Capability(0), nil)
	req.Header.Del("X-Forwarded-For")
	assertLocal404(t, do(t, req))

	hh = newHandlerHarness(t, func(o *Options) {
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})

	req = newRequest(t, hh.srv.URL, http.MethodGet, "/?bridge="+hh.h.Capability(0), nil)
	assertLocal404(t, do(t, req))
	assert.Equal(t, 0, hh.public.count())
}

func TestEmptyTrustedProxiesMeansLoopback(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, func(o *Options) {
		o.TrustedProxies = []netip.Prefix{}
	})

	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}, hh.h.trusted)

	// The test server is on loopback: the bridge is served.
	hh.bridge(t, 0)
}

func TestSessionCreateRejectsBadHello(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)
	boot := hh.bridge(t, 0)

	cases := map[string]func(*http.Request){
		"no content type":  func(r *http.Request) { r.Header.Del("Content-Type") },
		"text content":     func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"two content type": func(r *http.Request) { r.Header.Add("Content-Type", octetStream) },
		"bad hello": func(r *http.Request) {
			body := EncodeFrame(FrameHello, 0, []byte{2})
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		},
		"oversized": func(r *http.Request) {
			body := append(helloBody(), make([]byte, 64)...)
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		},
		"session token as bootstrap": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+hh.session(t, 0))
		},
		"no bearer prefix": func(r *http.Request) { r.Header.Set("Authorization", boot) },
	}

	for name, mutate := range cases {
		req := hh.createReq(t, boot)
		mutate(req)
		res := do(t, req)
		assertLocal404(t, res)
		assert.Empty(t, res.header.Get("X-Session-Token"), name)
	}

	// the bootstrap was not consumed by any of these
	res := do(t, hh.createReq(t, boot))
	assert.Equal(t, http.StatusOK, res.status)
}

func TestSessionCreate503WhenFull(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, func(o *Options) {
		o.Limits = DefaultLimits()
		o.Limits.MaxSessions = 1
	})

	first := hh.session(t, 0)
	boot := hh.bridge(t, 0)

	res := do(t, hh.createReq(t, boot))
	assert.Equal(t, http.StatusServiceUnavailable, res.status)
	assert.Equal(t, "1", res.header.Get("Retry-After"))
	assert.Equal(t, "no-store", res.header.Get("Cache-Control"))
	assert.Empty(t, res.header.Get("X-Session-Token"))

	assert.Equal(t, http.StatusNoContent, hh.deleteSession(t, first).status)

	res = do(t, hh.createReq(t, boot))
	require.Equal(t, http.StatusOK, res.status)
	assert.Len(t, res.header.Get("X-Session-Token"), tokenEncodedSize)

	// late DELETE of a closed session is still 204; an unknown one is 404
	assert.Equal(t, http.StatusNoContent, hh.deleteSession(t, first).status)
}

func TestSessionDeleteMalformedChunkedBodyIs404(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)
	token := hh.session(t, 0)

	conn, err := net.Dial("tcp", strings.TrimPrefix(hh.srv.URL, "http://"))
	require.NoError(t, err)

	defer conn.Close() //nolint: errcheck

	_, err = io.WriteString(conn, "DELETE /api/v1/session HTTP/1.1\r\n"+
		"Host: "+testHostname+"\r\n"+
		"X-Forwarded-For: "+testXFF+"\r\n"+
		"Authorization: Bearer "+token+"\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"zz\r\n")
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Empty(t, body)

	// The session survived the malformed DELETE.
	assert.Equal(t, 1, hh.h.Stats().SessionsLive)
	assert.Equal(t, http.StatusNoContent, hh.up(t, token, "1", batch(openFrame(1))).status)
}

func TestSessionDeleteUnknownIs404(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)
	token := hh.session(t, 0)

	other := newHandlerHarness(t, nil)
	// same derived key: the token is authentic there but unknown
	assertLocal404(t, other.deleteSession(t, token))
}

func TestProtocolErrorReleasesSession(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, func(o *Options) {
		o.Limits = DefaultLimits()
		o.Limits.MaxSessions = 1
	})

	token := hh.session(t, 0)

	// DATA on an unknown stream: protocol violation closes the session
	assertLocal404(t, hh.up(t, token, "1", batch(dataFrame(9, []byte("x")))))
	assert.Equal(t, 0, hh.h.Stats().SessionsLive)

	// the admission slot is free immediately
	hh.session(t, 0)
}

func TestShutdownClosesSessions(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)

	tokens := []string{hh.session(t, 0), hh.session(t, 1)}
	for i, token := range tokens {
		res := hh.up(t, token, "1", batch(openFrame(1)))
		require.Equal(t, http.StatusNoContent, res.status)
		waitServed(t, hh.serve, i+1)
	}

	// a parked long poll must not hold Shutdown
	pollDone := make(chan response, 1)

	go func() {
		pollDone <- hh.down(t, tokens[0], "0")
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	started := time.Now()
	require.NoError(t, hh.h.Shutdown(ctx))
	assert.Less(t, time.Since(started), 2*time.Second)

	for i := range 2 {
		conn := hh.serve.conn(t, i)
		// net.Pipe refuses deadlines once the peer is closed; the read then
		// returns io.EOF at once.
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))

		_, err := conn.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)
	}

	assert.Equal(t, 0, hh.h.Stats().SessionsLive)
	assert.Equal(t, 0, hh.h.Stats().StreamsLive)

	select {
	case res := <-pollDone:
		assert.Equal(t, http.StatusNotFound, res.status)
	case <-time.After(2 * time.Second):
		t.Fatal("parked poll did not return")
	}

	// authenticated routes are local 404 after shutdown, public still serves
	calls := hh.public.count()
	req := newRequest(t, hh.srv.URL, http.MethodGet, "/?bridge="+hh.h.Capability(0), nil)
	assertLocal404(t, do(t, req))

	res := do(t, newRequest(t, hh.srv.URL, http.MethodGet, "/", nil))
	assert.Equal(t, publicBody, string(res.body))
	assert.Equal(t, calls+1, hh.public.count())

	// idempotent
	require.NoError(t, hh.h.Shutdown(ctx))
}

func TestShutdownHonoursContext(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)
	token := hh.session(t, 0)

	// serve blocks: the uplink request stays in flight
	block := make(chan struct{})
	entered := make(chan struct{}, 1)

	hh.serve.mu.Lock()
	hh.serve.block = block
	hh.serve.entered = entered
	hh.serve.mu.Unlock()

	upDone := make(chan struct{})

	go func() {
		defer close(upDone)

		hh.up(t, token, "1", batch(openFrame(1)))
	}()

	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := hh.h.Shutdown(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "got %v", err)

	close(block)
	<-upDone

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	require.NoError(t, hh.h.Shutdown(ctx2))
	assert.Equal(t, 0, hh.h.Stats().SessionsLive)
	assert.Equal(t, 0, hh.h.Stats().StreamsLive)
}

func TestCapabilityMatchesProfile(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)

	for _, p := range testProfiles() {
		assert.Equal(t, Capability(p.Secret, testHostname), hh.h.Capability(p.Index))
	}

	assert.Empty(t, hh.h.Capability(7))
}

func TestHandlerLogsNoSecrets(t *testing.T) {
	t.Parallel()

	log := &recordingLogger{sink: &logSink{}}
	hh := newHandlerHarness(t, func(o *Options) { o.Logger = log })

	token := hh.session(t, 0)
	assertLocal404(t, hh.up(t, token, "1", batch(dataFrame(9, []byte("x")))))

	for _, line := range log.all() {
		assert.NotContains(t, line, token)
		assert.NotContains(t, line, hh.h.Capability(0))
		assert.False(t, strings.Contains(line, "Bearer"))
	}
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

// recordingLogger records every message with all bound names and values.
type recordingLogger struct {
	sink   *logSink
	prefix string
}

func (l *recordingLogger) bind(s string) mtglib.Logger {
	if l.sink == nil {
		l.sink = &logSink{}
	}

	return &recordingLogger{sink: l.sink, prefix: l.prefix + s + " "}
}

func (l *recordingLogger) add(msg string, err error) {
	if l.sink == nil {
		l.sink = &logSink{}
	}

	line := l.prefix + msg
	if err != nil {
		line += ": " + err.Error()
	}

	l.sink.mu.Lock()
	l.sink.lines = append(l.sink.lines, line)
	l.sink.mu.Unlock()
}

func (l *recordingLogger) all() []string {
	if l.sink == nil {
		return nil
	}

	l.sink.mu.Lock()
	defer l.sink.mu.Unlock()

	return slices.Clone(l.sink.lines)
}

func (l *recordingLogger) Named(name string) mtglib.Logger { return l.bind(name) }
func (l *recordingLogger) BindInt(name string, value int) mtglib.Logger {
	return l.bind(name + "=" + strconv.Itoa(value))
}
func (l *recordingLogger) BindStr(name, value string) mtglib.Logger {
	return l.bind(name + "=" + value)
}
func (l *recordingLogger) BindJSON(name, value string) mtglib.Logger {
	return l.bind(name + "=" + value)
}
func (l *recordingLogger) Printf(format string, args ...any) {
	l.add(fmt.Sprintf(format, args...), nil)
}
func (l *recordingLogger) Info(msg string)                    { l.add(msg, nil) }
func (l *recordingLogger) InfoError(msg string, err error)    { l.add(msg, err) }
func (l *recordingLogger) Warning(msg string)                 { l.add(msg, nil) }
func (l *recordingLogger) WarningError(msg string, err error) { l.add(msg, err) }
func (l *recordingLogger) Debug(msg string)                   { l.add(msg, nil) }
func (l *recordingLogger) DebugError(msg string, err error)   { l.add(msg, err) }

func TestSessionCreateSetsBodyDeadline(t *testing.T) {
	t.Parallel()

	hh := newHandlerHarness(t, nil)

	build := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/session", bytes.NewReader(helloBody()))
		r.RemoteAddr = "127.0.0.1:40000"
		r.Host = testHostname
		r.Header.Set("X-Forwarded-For", testXFF)
		r.Header.Set("Authorization", "Bearer "+hh.bridge(t, 0))
		r.Header.Set("Content-Type", octetStream)

		return r
	}

	rec := newDeadlineRecorder(nil)
	started := time.Now()
	hh.h.ServeHTTP(rec, build())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Len(t, rec.Header().Get("X-Session-Token"), tokenEncodedSize)
	assertBodyDeadline(t, rec, started)

	// A connection that refuses the deadline gets a local 404 and no
	// session.
	live := hh.h.Stats().SessionsLive
	rec = newDeadlineRecorder(errors.New("connection is gone"))
	hh.h.ServeHTTP(rec, build())

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Empty(t, rec.Header().Get("X-Session-Token"))
	assert.Equal(t, live, hh.h.Stats().SessionsLive)
}
