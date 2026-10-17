package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBootstrap = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-AbCdEf"

func renderTestBridge(t *testing.T) bridgePage {
	t.Helper()

	p, err := renderBridge("proxy.example.com", testBootstrap, 2<<20, 25000)
	require.NoError(t, err)

	return p
}

func TestRenderBridgeSubstitutes(t *testing.T) {
	p := renderTestBridge(t)
	body := string(p.Body)

	assert.NotRegexp(t, regexp.MustCompile(`__[A-Z_]+__`), body)
	assert.Len(t, p.Nonce, 24)

	raw, err := base64.RawURLEncoding.DecodeString(p.Nonce)
	require.NoError(t, err)
	assert.Len(t, raw, 18)

	assert.Contains(t, body, `nonce="`+p.Nonce+`"`)
	assert.Contains(t, body, `"https://proxy.example.com/"`)
	assert.Contains(t, body, `"`+testBootstrap+`"`)
	assert.Contains(t, body, "2097152")
	assert.Contains(t, body, "const LONG_POLL_MS = 25000;")
	assert.Equal(t, 1, strings.Count(body, "<script"))
	assert.Contains(t, body, "<title>Connection</title>")
	assert.True(t, strings.HasPrefix(body, "<!doctype html>"))

	other := renderTestBridge(t)
	assert.NotEqual(t, p.Nonce, other.Nonce)
}

func TestRenderBridgeEscapesValues(t *testing.T) {
	p, err := renderBridge("proxy.example.com", "</script><b>", 2<<20, 25000)
	require.NoError(t, err)
	assert.NotContains(t, string(p.Body), "</script><b>")
}

func TestRenderBridgeRejectsBadInput(t *testing.T) {
	_, err := renderBridge("", testBootstrap, 2<<20, 25000)
	require.Error(t, err)

	_, err = renderBridge("proxy.example.com", testBootstrap, 0, 25000)
	require.Error(t, err)

	_, err = renderBridge("proxy.example.com", testBootstrap, 2<<20, 0)
	require.Error(t, err)
}

func TestRenderBridgeFailsOnSurvivingPlaceholder(t *testing.T) {
	_, err := renderBridgeTemplate(bridgeTemplate+"__NONCE__", "proxy.example.com", testBootstrap, 2<<20, 25000)
	require.NoError(t, err) // all occurrences are substituted

	_, err = renderBridgeTemplate(strings.Replace(bridgeTemplate, "__BATCH_LIMIT__", "1", 1),
		"proxy.example.com", testBootstrap, 2<<20, 25000)
	require.Error(t, err) // a placeholder is missing from the template

	_, err = renderBridgeTemplate(strings.Replace(bridgeTemplate, "__LONG_POLL_MS__", "1", 1),
		"proxy.example.com", testBootstrap, 2<<20, 25000)
	require.Error(t, err) // the long-poll placeholder is missing from the template

	_, err = renderBridgeTemplate(bridgeTemplate, "proxy.example.com", "__LONG_POLL_MS__", 2<<20, 25000)
	require.Error(t, err) // the long-poll placeholder survives

	_, err = renderBridgeTemplate(bridgeTemplate, "proxy.example.com", "__BOOTSTRAP__", 2<<20, 25000)
	require.Error(t, err) // a placeholder survives
}

func TestRenderBridgeIsSelfContained(t *testing.T) {
	body := string(renderTestBridge(t).Body)

	for _, s := range []string{
		"src=", "href=", "@import", "url(", "<link", "<img", "<iframe",
		"localStorage", "sessionStorage", "indexedDB", "document.cookie",
		"http://", "<style", "<base", "<form",
	} {
		assert.NotContains(t, body, s)
	}
}

func TestWriteBridgeHeaders(t *testing.T) {
	p := renderTestBridge(t)
	rec := httptest.NewRecorder()
	writeBridge(rec, p)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))

	csp := strings.Join([]string{
		"default-src 'none'",
		"script-src 'nonce-" + p.Nonce + "'",
		"connect-src 'self' wss://proxy.example.com",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors http://127.0.0.1:*",
		"sandbox allow-same-origin allow-scripts",
	}, "; ")
	assert.Equal(t, csp, rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, csp, p.CSP)

	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "off", rec.Header().Get("X-DNS-Prefetch-Control"))
	assert.Equal(t, permissionsPolicy, rec.Header().Get("Permissions-Policy"))

	policy := strings.Split(rec.Header().Get("Permissions-Policy"), ", ")
	for _, f := range []string{
		"camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()", "midi=()",
		"magnetometer=()", "gyroscope=()", "accelerometer=()", "display-capture=()",
		"fullscreen=()", "picture-in-picture=()", "publickey-credentials-get=()",
		"screen-wake-lock=()", "xr-spatial-tracking=()",
	} {
		assert.Contains(t, policy, f)
	}

	seen := map[string]bool{}
	for _, f := range policy {
		assert.Regexp(t, `^[a-z-]+=\(\)$`, f)
		assert.False(t, seen[f], "duplicate %s", f)
		seen[f] = true
	}
	assert.Empty(t, rec.Header().Values("X-Frame-Options"))
	assert.Equal(t, strconv.Itoa(len(p.Body)), rec.Header().Get("Content-Length"))
	assert.Equal(t, p.Body, rec.Body.Bytes())
}

func TestBridgeScriptMentionsContract(t *testing.T) {
	body := string(renderTestBridge(t).Body)

	for _, s := range []string{
		"tproxy-android-init", "tproxy-init", "TelegramWebProxy",
		"api/v1/session", "api/v1/up", "api/v1/down",
		"X-Up-Seq", "X-Up-Ack", "X-Down-Cursor", "X-Carrier-Mode", "X-Session-Token",
		"credentials:'omit'", "redirect:'error'", "mode:'same-origin'", "cache:'no-store'",
		"referrerPolicy:'no-referrer'", "keepalive:true", "pagehide", "history.replaceState",
		"'connecting'", "'connected'", "'reconnecting'", "'failed'", "'use strict'",
	} {
		assert.Contains(t, body, s)
	}
}
