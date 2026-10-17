package web

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomB64(t testing.TB) string {
	t.Helper()

	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestScannerFindsSecrets(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t, "scan")
	tok, _, err := signer.issue(tokenSession)
	require.NoError(t, err)

	capability := randomB64(t)
	scanner := newSecretScanner(signer, []string{capability, "short", "!!notbase64!!"})

	build := func(target string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}

		return r
	}

	tests := map[string]struct {
		req  *http.Request
		want bool
	}{
		"capability query":    {build("/?bridge="+capability, nil), true},
		"capability mid":      {build("/x?a="+capability+"&b=1", nil), true},
		"bearer":              {build("/", map[string]string{"Authorization": "Bearer " + tok}), true},
		"percent encoded":     {build("/", map[string]string{"X-Foo": "zz%" + "41" + url.PathEscape(tok)}), true},
		"percent in token":    {build("/", map[string]string{"X-Foo": percentEncodeAll(tok)}), true},
		"cookie":              {build("/", map[string]string{"Cookie": "s=" + tok}), true},
		"random query":        {build("/?bridge="+randomB64(t), nil), false},
		"random bearer":       {build("/", map[string]string{"Authorization": "Bearer " + randomB64(t)}), false},
		"short prefix":        {build("/", map[string]string{"X-Foo": tok[:42]}), false},
		"adjacent chars":      {build("/", map[string]string{"X-Foo": "AAAA" + tok + "BBBB"}), false},
		"no headers":          {build("/", nil), false},
		"capability in path":  {build("/"+capability, nil), true},
		"capability w/ extra": {build("/?q=-"+capability, nil), true},
	}

	// "adjacent chars" is a run longer than 43; the window scan still finds T.
	tests["adjacent chars"] = struct {
		req  *http.Request
		want bool
	}{tests["adjacent chars"].req, true}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, scanner.requestCarriesSecret(tt.req))
		})
	}

	t.Run("header name after canonicalization", func(t *testing.T) {
		t.Parallel()

		// net/http canonicalizes header names (textproto), which destroys
		// the case of base64, so a token used as a header name is not
		// recoverable. The same token as a value is detected.
		asName := "GET / HTTP/1.1\r\nHost: example.com\r\n" + tok + ": 1\r\n\r\n"
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(asName)))
		require.NoError(t, err)
		assert.False(t, scanner.requestCarriesSecret(r))

		asValue := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Foo: " + tok + "\r\n\r\n"
		r, err = http.ReadRequest(bufio.NewReader(strings.NewReader(asValue)))
		require.NoError(t, err)
		assert.True(t, scanner.requestCarriesSecret(r))
	})

	t.Run("header name verbatim", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header[tok] = []string{"1"}

		assert.True(t, scanner.requestCarriesSecret(r))
	})

	t.Run("malformed escape before encoded token", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Foo", "%zz"+percentEncodeAll(tok))

		assert.True(t, scanner.requestCarriesSecret(r))
	})

	t.Run("malformed escape alone", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Foo", "%zz")

		assert.False(t, scanner.requestCarriesSecret(r))
	})

	t.Run("second header value", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("X-Foo", "a")
		r.Header.Add("X-Foo", tok)

		assert.True(t, scanner.requestCarriesSecret(r))
	})

	t.Run("host", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = capability + ".example.com"

		assert.True(t, scanner.requestCarriesSecret(r))
	})

	t.Run("1000 random headers", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		for range 1000 {
			r.Header.Add("X-"+randomB64(t)[:8], randomB64(t))
		}

		assert.False(t, scanner.requestCarriesSecret(r))
	})
}

func percentEncodeAll(s string) string {
	const hexdigits = "0123456789ABCDEF"

	out := make([]byte, 0, len(s)*3)
	for i := range len(s) {
		out = append(out, '%', hexdigits[s[i]>>4], hexdigits[s[i]&15])
	}

	return string(out)
}

// scanRunReference is the straightforward scan: one decode per 43-char
// window at every offset. scanRun must find exactly what it finds.
func (s *secretScanner) scanRunReference(run string) bool {
	for i := 0; i+tokenEncodedSize <= len(run); i++ {
		raw, err := base64.RawURLEncoding.DecodeString(run[i : i+tokenEncodedSize])
		if err != nil {
			continue
		}

		if _, _, ok := s.signer.classify(raw); ok {
			return true
		}

		for _, c := range s.capabilities {
			if subtle.ConstantTimeCompare(raw, c) == 1 {
				return true
			}
		}
	}

	return false
}

func randomTokenChars(t testing.TB, n int) string {
	t.Helper()

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	raw := make([]byte, n)
	_, err := rand.Read(raw)
	require.NoError(t, err)

	for i := range raw {
		raw[i] = alphabet[raw[i]&63]
	}

	return string(raw)
}

func TestScanRunMatchesReference(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t, "scan-equivalence")
	tok, _, err := signer.issue(tokenBootstrap)
	require.NoError(t, err)

	capability := randomB64(t)
	// A capability whose last char has non-zero padding bits: a lenient
	// decode of this window yields the capability, as the reference finds.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	last := strings.IndexByte(alphabet, capability[42])
	sloppy := capability[:42] + string(alphabet[last^1]) // flips a padding bit

	scanner := newSecretScanner(signer, []string{capability})

	for _, secret := range []string{tok, capability, sloppy} {
		for prefix := range 9 {
			for suffix := range 9 {
				run := randomTokenChars(t, prefix) + secret + randomTokenChars(t, suffix)

				want := scanner.scanRunReference(run)
				assert.True(t, want, "prefix=%d suffix=%d", prefix, suffix)
				assert.Equal(t, want, scanner.scanRun(run), "prefix=%d suffix=%d", prefix, suffix)

				// Truncating the secret by one char at either end breaks it.
				cut := run[:prefix] + secret[1:] + run[prefix+len(secret):]
				assert.Equal(t, scanner.scanRunReference(cut), scanner.scanRun(cut))

				cut = run[:prefix+len(secret)-1] + run[prefix+len(secret):]
				assert.Equal(t, scanner.scanRunReference(cut), scanner.scanRun(cut))
			}
		}
	}

	for n := range 300 {
		run := randomTokenChars(t, n)
		assert.Equal(t, scanner.scanRunReference(run), scanner.scanRun(run), "len=%d", n)
	}
}

func longTokenHeaderRequest(tb testing.TB, size int) *http.Request {
	tb.Helper()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Foo", randomTokenChars(tb, size))

	return r
}

func BenchmarkRequestCarriesSecret16KiB(b *testing.B) {
	scanner := newSecretScanner(newTestSigner(b, "bench"), []string{randomB64(b)})
	r := longTokenHeaderRequest(b, 16<<10)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if scanner.requestCarriesSecret(r) {
			b.Fatal("unexpected secret")
		}
	}
}

// TestScannerScansRunWithFewAllocations pins the per-alignment scan by its
// allocation count, which is deterministic, instead of by wall time, which
// depends on the machine: the per-offset reference allocates once per
// window, the per-alignment scan once per alignment.
func TestScannerScansRunWithFewAllocations(t *testing.T) {
	scanner := newSecretScanner(newTestSigner(t, "allocs"), []string{randomB64(t)})
	run := randomTokenChars(t, 16<<10)

	fast := testing.AllocsPerRun(10, func() {
		if scanner.scanRun(run) {
			t.Error("unexpected secret")
		}
	})
	reference := testing.AllocsPerRun(10, func() {
		if scanner.scanRunReference(run) {
			t.Error("unexpected secret")
		}
	})

	t.Logf("16 KiB run: per-alignment %.0f allocs, per-offset reference %.0f allocs", fast, reference)
	assert.LessOrEqual(t, fast, 16.0)
	assert.Greater(t, reference, fast*64)
}
