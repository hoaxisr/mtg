package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicUpstreamProxiesHostAndPath(t *testing.T) {
	var gotHost, gotPath, gotQuery string

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath, gotQuery = r.Host, r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	u, _ := url.Parse(up.URL)
	h, err := NewPublicUpstream(u)
	require.NoError(t, err)

	r := httptest.NewRequest("GET", "http://site.example.org/a/b?c=d", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "site.example.org", gotHost)
	assert.Equal(t, "/a/b", gotPath)
	assert.Equal(t, "c=d", gotQuery)
}

func TestPublicUpstreamForwardedHeaders(t *testing.T) {
	var got http.Header

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()

	u, _ := url.Parse(up.URL)
	h, err := NewPublicUpstream(u)
	require.NoError(t, err)

	srv := httptest.NewServer(h)
	defer srv.Close()

	send := func(xff string, hdr ...string) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
		require.NoError(t, err)

		req.Host = "site.example.org"
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}

		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
	}

	send("203.0.113.7")
	assert.Equal(t, []string{"203.0.113.7, 127.0.0.1"}, got.Values("X-Forwarded-For"))
	assert.Equal(t, "site.example.org", got.Get("X-Forwarded-Host"))
	assert.Equal(t, "http", got.Get("X-Forwarded-Proto"))

	send("")
	assert.Equal(t, []string{"127.0.0.1"}, got.Values("X-Forwarded-For"))
	assert.Equal(t, "site.example.org", got.Get("X-Forwarded-Host"))
	assert.Equal(t, "http", got.Get("X-Forwarded-Proto"))

	// the TLS-terminating front proxy's values are kept
	send("203.0.113.7", "X-Forwarded-Proto", "https", "X-Forwarded-Host", "front.example.org")
	assert.Equal(t, []string{"https"}, got.Values("X-Forwarded-Proto"))
	assert.Equal(t, []string{"front.example.org"}, got.Values("X-Forwarded-Host"))
	assert.Equal(t, []string{"203.0.113.7, 127.0.0.1"}, got.Values("X-Forwarded-For"))
}

func TestPublicUpstreamBadGateway(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	h, err := NewPublicUpstream(u)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, 502, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestPublicUpstreamRejects(t *testing.T) {
	for _, s := range []string{
		"https://127.0.0.1:3000", "http://example.com", "http://127.0.0.1:3000/base",
		"http://8.8.8.8", "http://u@127.0.0.1", "http://127.0.0.1/?a=b", "http://127.0.0.1/#f",
	} {
		u, err := url.Parse(s)
		require.NoError(t, err)
		_, err = NewPublicUpstream(u)
		assert.Error(t, err, s)
	}

	for _, s := range []string{"http://127.0.0.1:3000", "http://10.1.2.3/", "http://[::1]:80", "http://169.254.1.1"} {
		u, _ := url.Parse(s)
		_, err := NewPublicUpstream(u)
		assert.NoError(t, err, s)
	}
}

func TestPublicDir(t *testing.T) {
	dir := t.TempDir()
	write := func(n, c string) { require.NoError(t, os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600)) }
	write("index.html", "INDEX")
	write("about.html", "ABOUT")
	write("404.html", "NOTFOUND")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0o700))

	h, err := NewPublicDir(dir)
	require.NoError(t, err)

	do := func(method, p string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, p, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := do("GET", "/")
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "INDEX", w.Body.String())

	w = do("GET", "/about.html")
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "ABOUT", w.Body.String())

	w = do("GET", "/missing")
	assert.Equal(t, 404, w.Code)
	assert.Equal(t, "NOTFOUND", w.Body.String())
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))

	assert.Equal(t, 404, do("GET", "/assets/").Code)
	assert.Equal(t, 404, do("GET", "/assets").Code)
	assert.Equal(t, 404, do("GET", "/../etc/passwd").Code)
	assert.Equal(t, 405, do("POST", "/").Code)

	w = do("GET", "/about.html", "Range", "bytes=0-1")
	assert.Equal(t, 206, w.Code)
	assert.Equal(t, "AB", w.Body.String())

	_, err = NewPublicDir(filepath.Join(dir, "index.html"))
	assert.Error(t, err)
	_, err = NewPublicDir(filepath.Join(dir, "nope"))
	assert.Error(t, err)
}
