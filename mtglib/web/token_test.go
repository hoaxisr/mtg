package web

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSigner(t testing.TB, seed string) *tokenSigner {
	t.Helper()

	signer, err := newTokenSigner(deriveTokenKey([]byte(seed)))
	require.NoError(t, err)

	return signer
}

func TestTokenIssueVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t, "one")
	other := newTestSigner(t, "two")

	tok, hash, err := signer.issue(tokenBootstrap)
	require.NoError(t, err)
	assert.Len(t, tok, 43)

	got, ok := signer.verifyBearer(tok, tokenBootstrap)
	assert.True(t, ok)
	assert.Equal(t, hash, got)

	_, ok = signer.verifyBearer(tok, tokenSession)
	assert.False(t, ok)

	flipped := []byte(tok)
	if flipped[5] == 'A' {
		flipped[5] = 'B'
	} else {
		flipped[5] = 'A'
	}

	_, ok = signer.verifyBearer(string(flipped), tokenBootstrap)
	assert.False(t, ok)

	_, ok = other.verifyBearer(tok, tokenBootstrap)
	assert.False(t, ok)

	_, ok = signer.verifyBearer(tok+"=", tokenBootstrap)
	assert.False(t, ok)

	_, ok = signer.verifyBearer("", tokenBootstrap)
	assert.False(t, ok)
}

func TestTokenNonCanonicalEncoding(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t, "one")

	tok, _, err := signer.issue(tokenSession)
	require.NoError(t, err)

	// the last char of 43-char base64 carries 4 unused bits; changing them
	// decodes to the same bytes but is not canonical.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	last := tok[42]
	idx := -1

	for i := range len(alphabet) {
		if alphabet[i] == last {
			idx = i
		}
	}

	require.GreaterOrEqual(t, idx, 0)

	alt := tok[:42] + string(alphabet[idx^1])
	raw1, err1 := base64.RawURLEncoding.DecodeString(tok)
	raw2, err2 := base64.RawURLEncoding.DecodeString(alt)
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, raw1, raw2)

	_, ok := signer.verifyBearer(alt, tokenSession)
	assert.False(t, ok)

	_, ok = signer.verifyBearer(tok, tokenSession)
	assert.True(t, ok)
}

func TestTokenSignerBadKey(t *testing.T) {
	t.Parallel()

	_, err := newTokenSigner(make([]byte, 16))
	assert.Error(t, err)
}

func TestTokenClassifyTag(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t, "one")

	for _, kind := range []tokenKind{tokenBootstrap, tokenSession} {
		tok, hash, err := signer.issue(kind)
		require.NoError(t, err)

		raw, err := base64.RawURLEncoding.DecodeString(tok)
		require.NoError(t, err)

		gotKind, gotHash, ok := signer.classify(raw)
		assert.True(t, ok)
		assert.Equal(t, kind, gotKind)
		assert.Equal(t, hash, gotHash)

		bad := append([]byte(nil), raw...)
		bad[13] ^= 1
		_, _, ok = signer.classify(bad)
		assert.False(t, ok)

		bad = append([]byte(nil), raw...)
		bad[31] ^= 1
		_, _, ok = signer.classify(bad)
		assert.False(t, ok)

		_, _, ok = signer.classify(raw[:31])
		assert.False(t, ok)

		// tag is deterministic for the same nonce
		again := append([]byte(nil), raw...)
		copy(again[16:], make([]byte, 16))
		assert.Equal(t, signer.tag(raw[:12]), signer.tag(again[:12]))
		assert.Equal(t, raw[12:16], signer.tag(raw[:12]))
	}
}

func TestTokenRandomRawRejected(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t, "one")

	for range 1000 {
		raw := make([]byte, 32)
		_, err := rand.Read(raw)
		require.NoError(t, err)

		_, _, ok := signer.classify(raw)
		assert.False(t, ok)
	}
}

func TestDeriveTokenKeyStable(t *testing.T) {
	t.Parallel()

	a := deriveTokenKey([]byte("a"))
	assert.Len(t, a, 32)
	assert.Equal(t, a, deriveTokenKey([]byte("a")))
	assert.NotEqual(t, a, deriveTokenKey([]byte("b")))
}
