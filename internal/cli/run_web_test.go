package cli

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/events"
	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/logger"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/mtglib/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const webTestIndex = "<html>hello from public dir</html>"

type webTestAllowAll struct{}

func (webTestAllowAll) Contains(net.IP) bool { return true }
func (webTestAllowAll) Run(time.Duration)    {}
func (webTestAllowAll) Shutdown()            {}

func webTestPublicDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(webTestIndex), 0o600))

	return dir
}

func webTestConfig(t *testing.T, extra string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"
` + extra))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	return conf
}

func webTestEnabledConfig(t *testing.T) *config.Config {
	t.Helper()

	return webTestConfig(t, `
[web]
enabled = true
bind-to = "127.0.0.1:8443"
hostname = "web.example.com"
public-dir = "`+webTestPublicDir(t)+`"
`)
}

func webTestProxy(t *testing.T, conf *config.Config) *mtglib.Proxy {
	t.Helper()

	ntw, err := makeNetwork(conf, "test")
	require.NoError(t, err)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Logger:          logger.NewNoopLogger(),
		Network:         ntw,
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     webTestAllowAll{},
		EventStream:     events.NewNoopStream(),
		Secret:          conf.Secret,
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	return proxy
}

func TestMakeWebHandlerDisabled(t *testing.T) {
	conf := webTestConfig(t, "")

	handler, err := makeWebHandler(conf, webTestProxy(t, conf), logger.NewNoopLogger())
	require.NoError(t, err)
	require.Nil(t, handler)
}

func TestMakeWebHandlerFromConfig(t *testing.T) {
	conf := webTestEnabledConfig(t)

	handler, err := makeWebHandler(conf, webTestProxy(t, conf), logger.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, handler)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		handler.Shutdown(ctx) //nolint: errcheck
	})

	require.Equal(t, web.Capability(conf.Secret, "web.example.com"), handler.Capability(0))
}

func TestServeWebRoundTrip(t *testing.T) {
	conf := webTestEnabledConfig(t)
	log := logger.NewNoopLogger()

	handler, err := makeWebHandler(conf, webTestProxy(t, conf), log)
	require.NoError(t, err)
	require.NotNil(t, handler)

	// web.bind-to cannot be port 0, so pass an own ephemeral listener.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	shutdown := serveWebListener(t.Context(), conf, handler, listener, log)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+listener.Addr().String()+"/", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint: errcheck
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, webTestIndex, string(body))

	done := make(chan struct{})

	go func() {
		shutdown()
		shutdown() // idempotent
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not return within 2s")
	}
}

// webTestRequest builds an authenticated-path request as a reverse proxy on
// loopback would forward it.
func webTestRequest(t *testing.T, method, url string, body []byte) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
	require.NoError(t, err)

	req.Host = "web.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	return req
}

func webTestDo(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp, body
}

// TestServeWebShutdownReleasesParkedPoll checks the shutdown order: a /down
// long poll parked on the server must not hold shutdown for the whole
// web.timeouts.shutdown budget.
func TestServeWebShutdownReleasesParkedPoll(t *testing.T) {
	conf := webTestConfig(t, `
[web]
enabled = true
bind-to = "127.0.0.1:8443"
hostname = "web.example.com"
public-dir = "`+webTestPublicDir(t)+`"

[web.timeouts]
long-poll = "5s"
shutdown = "4s"
`)
	log := logger.NewNoopLogger()

	handler, err := makeWebHandler(conf, webTestProxy(t, conf), log)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	base := "http://" + listener.Addr().String()
	shutdown := serveWebListener(t.Context(), conf, handler, listener, log)

	resp, page := webTestDo(t, webTestRequest(t, http.MethodGet, base+"/?bridge="+handler.Capability(0), nil))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	m := regexp.MustCompile(`const BOOTSTRAP = "([A-Za-z0-9_-]{43})";`).FindSubmatch(page)
	require.NotNil(t, m)

	req := webTestRequest(t, http.MethodPost, base+"/api/v1/session", web.EncodeFrame(web.FrameHello, 0, []byte{1}))
	req.Header.Set("Authorization", "Bearer "+string(m[1]))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, _ = webTestDo(t, req)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := resp.Header.Get("X-Session-Token")
	require.NotEmpty(t, token)

	polled := make(chan int, 1)

	go func() {
		req := webTestRequest(t, http.MethodPost, base+"/api/v1/down", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Down-Cursor", "0")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			polled <- 0

			return
		}

		resp.Body.Close() //nolint: errcheck
		polled <- resp.StatusCode
	}()

	require.Eventually(t, func() bool { return handler.Stats().SessionsLive == 1 },
		time.Second, 5*time.Millisecond)
	time.Sleep(200 * time.Millisecond) // let the poll park

	started := time.Now()

	shutdown()

	assert.Less(t, time.Since(started), 2*time.Second)

	select {
	case status := <-polled:
		assert.Equal(t, http.StatusNotFound, status)
	case <-time.After(2 * time.Second):
		t.Fatal("parked poll did not return")
	}
}

func TestServeWebOptionsAsteriskReachesHandler(t *testing.T) {
	conf := webTestEnabledConfig(t)
	log := logger.NewNoopLogger()

	handler, err := makeWebHandler(conf, webTestProxy(t, conf), log)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	shutdown := serveWebListener(t.Context(), conf, handler, listener, log)
	t.Cleanup(shutdown)

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	defer conn.Close() //nolint: errcheck

	_, err = io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: web.example.com\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)

	defer resp.Body.Close() //nolint: errcheck

	// net/http's general OPTIONS handler would answer 200; the public dir
	// answers 405 to anything but GET and HEAD.
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestServeWebDisabled(t *testing.T) {
	conf := webTestConfig(t, "")

	shutdown, err := serveWeb(t.Context(), conf, nil, logger.NewNoopLogger())
	require.NoError(t, err)
	require.Nil(t, shutdown)
}
