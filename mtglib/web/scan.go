package web

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// secretScanner detects tokens and capabilities in an HTTP request.
//
// Header names are scanned on a best-effort basis only: net/http
// canonicalizes names (textproto), which destroys base64 case, so a token
// placed in a name is usually unrecoverable. Only a name which survives
// canonicalization unchanged can match.
type secretScanner struct {
	signer       *tokenSigner
	capabilities [][]byte
}

// newSecretScanner builds a scanner which detects tokens issued by signer
// and any of capabilities (base64url strings) in a request.
func newSecretScanner(signer *tokenSigner, capabilities []string) *secretScanner {
	decoded := make([][]byte, 0, len(capabilities))

	for _, c := range capabilities {
		raw, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil || len(raw) != tokenRawSize {
			continue
		}

		decoded = append(decoded, raw)
	}

	return &secretScanner{signer: signer, capabilities: decoded}
}

func (s *secretScanner) requestCarriesSecret(r *http.Request) bool {
	if s.scan(r.URL.RequestURI()) || s.scan(r.Host) {
		return true
	}

	for name, values := range r.Header {
		if s.scan(name) {
			return true
		}

		for _, v := range values {
			if s.scan(v) {
				return true
			}
		}
	}

	return false
}

func isTokenChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
}

func (s *secretScanner) scan(input string) bool {
	if s.scanString(input) {
		return true
	}

	if strings.IndexByte(input, '%') < 0 {
		return false // nothing to unescape
	}

	decoded := lenientUnescape(input)

	return decoded != input && s.scanString(decoded)
}

// lenientUnescape decodes %XX sequences with valid hex digits and copies
// everything else verbatim, so a malformed escape does not disable decoding
// of the rest of the input.
func lenientUnescape(input string) string {
	out := make([]byte, 0, len(input))

	for i := 0; i < len(input); i++ {
		if input[i] == '%' && i+2 < len(input) && unhex(input[i+1]) >= 0 && unhex(input[i+2]) >= 0 {
			out = append(out, byte(unhex(input[i+1])<<4|unhex(input[i+2])))
			i += 2

			continue
		}

		out = append(out, input[i])
	}

	return string(out)
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}

	return -1
}

func (s *secretScanner) scanString(input string) bool {
	start := 0

	for i := 0; i <= len(input); i++ {
		if i < len(input) && isTokenChar(input[i]) {
			continue
		}

		if i-start >= tokenEncodedSize && s.scanRun(input[start:i]) {
			return true
		}

		start = i + 1
	}

	return false
}

// scanRun reports whether any window of tokenEncodedSize chars of run (a
// run of base64url chars) decodes to an authentic token or a capability.
//
// It does not decode every window on its own. Let a window start at offset
// i = a + 4j with a = i mod 4. Its first 40 chars are whole quads, which
// decode to the same 30 bytes as at [3j, 3j+30) in the decoding of run[a:].
// Its last 3 chars are the first 3 chars of the next quad, and the first 2
// bytes of a quad depend on those 3 chars only, so the window decodes to
// exactly run[a:]-decoded[3j : 3j+32]. The lenient (non-strict) decoder
// ignores the padding bits of a lone window's last char just as they are
// ignored, being bits of the next byte, inside a whole quad. Hence the run
// is decoded once per alignment and each window is a 32-byte slice of that.
func (s *secretScanner) scanRun(run string) bool {
	src := []byte(run)
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(src)))
	scratch := make([]byte, 2*tokenFilterBlockSize)

	for align := 0; align < 4 && align+tokenEncodedSize <= len(src); align++ {
		part := src[align:]
		if len(part)%4 == 1 {
			// A lone char of a final quad is not decodable, and no window
			// of this alignment ends on it.
			part = part[:len(part)-1]
		}

		n, err := base64.RawURLEncoding.Decode(dst, part)
		if err != nil {
			continue // cannot happen: run holds base64url chars only
		}

		// off+32 <= n holds exactly when the window at align+off/3*4 fits
		// into run.
		for off := 0; off+tokenRawSize <= n; off += 3 {
			if s.matches(dst[off:off+tokenRawSize], scratch) {
				return true
			}
		}
	}

	return false
}

// matches reports whether raw (32 bytes) is a capability or an authentic
// token. scratch is a reusable buffer for the token filter.
func (s *secretScanner) matches(raw, scratch []byte) bool {
	found := false

	for _, c := range s.capabilities {
		if subtle.ConstantTimeCompare(raw, c) == 1 {
			found = true
		}
	}

	if found {
		return true
	}

	// The cheap filter tag rejects nearly every random window before a MAC
	// is computed.
	if !s.signer.tagMatches(raw, scratch) {
		return false
	}

	_, _, ok := s.signer.classify(raw)

	return ok
}
