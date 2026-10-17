package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBridge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 chars

func TestClassifyTable(t *testing.T) {
	require.Len(t, testBridge, 43)

	const host = "proxy.example.com"

	tests := []struct {
		name    string
		method  string
		target  string
		host    string
		headers map[string][]string
		secret  bool
		want    routeKind
	}{
		{"stranger", "POST", "/anything?x=1", "whatever", nil, false, routePublic},
		{"bridge", "GET", "/?bridge=" + testBridge, host, nil, true, routeBridge},
		{"bridge cookie", "GET", "/?bridge=" + testBridge, host, map[string][]string{"Cookie": {"a=b"}}, true, routeBridge},
		{"bridge two auth", "GET", "/?bridge=" + testBridge, host, map[string][]string{"Authorization": {"a", "b"}}, true, routeBridge},
		{"bridge extra", "GET", "/?bridge=" + testBridge + "&x=1", host, nil, true, routeLocal404},
		{"bridge case", "GET", "/?Bridge=" + testBridge, host, nil, true, routeLocal404},
		{"bridge short", "GET", "/?bridge=abc", host, nil, true, routeLocal404},
		{"up query", "POST", "/api/v1/up?x=1", host, nil, true, routeLocal404},
		{"up cookie", "POST", "/api/v1/up", host, map[string][]string{"Cookie": {"a=b"}}, true, routeLocal404},
		{"two auth", "POST", "/api/v1/up", host, map[string][]string{"Authorization": {"a", "b"}}, true, routeLocal404},
		{"one auth", "POST", "/api/v1/up", host, map[string][]string{"Authorization": {"a"}}, true, routeUp},
		{"ws cookie", "GET", "/api/v1/ws", host, map[string][]string{"Cookie": {"a=b"}}, true, routeWS},
		{"host upper port", "POST", "/api/v1/up", "PROXY.EXAMPLE.COM:443", nil, true, routeUp},
		{"other host", "POST", "/api/v1/up", "other.example.com", nil, true, routeLocal404},
		{"get up", "GET", "/api/v1/up", host, nil, true, routeLocal404},
		{"session create", "POST", "/api/v1/session", host, nil, true, routeSessionCreate},
		{"session delete", "DELETE", "/api/v1/session", host, nil, true, routeSessionDelete},
		{"down", "POST", "/api/v1/down", host, nil, true, routeDown},
		{"escaped path", "POST", "/api/v1/%75p", host, nil, true, routeLocal404},
		{"other path", "GET", "/foo", host, nil, true, routeLocal404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.target, nil)
			r.Host = tt.host
			r.Header = http.Header{}
			for k, vs := range tt.headers {
				r.Header[k] = vs
			}
			assert.Equal(t, tt.want, classify(r, host, tt.secret))
		})
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string
		fail   bool
	}{
		{"ok", "127.0.0.1:5", []string{"203.0.113.9"}, "203.0.113.9", false},
		{"ok spaces", "127.0.0.1:5", []string{" 203.0.113.9 "}, "203.0.113.9", false},
		{"chain", "127.0.0.1:5", []string{"203.0.113.9, 10.0.0.1"}, "", true},
		{"missing", "127.0.0.1:5", nil, "", true},
		{"two headers", "127.0.0.1:5", []string{"203.0.113.9", "203.0.113.8"}, "", true},
		{"untrusted", "192.0.2.1:5", []string{"203.0.113.9"}, "", true},
		{"v6", "[::1]:5", []string{"2001:db8::1"}, "2001:db8::1", false},
		{"port", "127.0.0.1:5", []string{"203.0.113.9:80"}, "", true},
		{"bad remote", "nonsense", []string{"203.0.113.9"}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			r.Header = http.Header{}
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			ip, err := clientIP(r, trusted)
			if tt.fail {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, ip.String())
		})
	}
}

func TestCanonicalUint(t *testing.T) {
	for s, want := range map[string]uint64{"0": 0, "1": 1, "42": 42} {
		v, err := canonicalUint(s)
		require.NoError(t, err)
		assert.Equal(t, want, v)
	}

	for _, s := range []string{"01", "+1", "-1", "", "1a", strings.Repeat("1", 21), "18446744073709551616"} {
		_, err := canonicalUint(s)
		assert.Error(t, err, s)
	}
}

func TestLocalNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	localNotFound(w)
	assert.Equal(t, 404, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "0", w.Header().Get("Content-Length"))
	assert.Empty(t, w.Body.String())
}
