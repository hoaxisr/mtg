package web_test

import (
	"strings"
	"testing"

	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/mtglib/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSecret() mtglib.Secret {
	var s mtglib.Secret

	for i := range s.Key {
		s.Key[i] = byte(i)
	}

	return s
}

func TestCapabilityVector(t *testing.T) {
	t.Parallel()

	got := web.Capability(testSecret(), "proxy.example.com")
	assert.Equal(t, "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA", got)
	assert.Len(t, got, 43)
}

func TestWebSecret(t *testing.T) {
	t.Parallel()

	got := web.WebSecret(testSecret())
	assert.Equal(t, "dd000102030405060708090a0b0c0d0e0f", got)
	assert.Len(t, got, 34)
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"proxy.example.com":              true,
		"Proxy.example.com":              false,
		"proxy.example.com:443":          false,
		"127.0.0.1":                      false,
		"xn--80ak6aa92e.com":             true,
		"-bad.com":                       false,
		"bad-.com":                       false,
		strings.Repeat("a", 63) + ".com": true,
		strings.Repeat("a", 64) + ".com": false,
		"":                               false,
		"proxy.example.com.":             false,
		"a..b":                           false,
		"under_score.com":                false,
		strings.Repeat("a.", 127) + "a":  false,
	}

	for h, ok := range tests {
		err := web.ValidateHostname(h)
		if ok {
			assert.NoError(t, err, h)
		} else {
			require.Error(t, err, h)
			assert.ErrorIs(t, err, web.ErrHostname, h)
		}
	}
}

func TestLinks(t *testing.T) {
	t.Parallel()

	tg, tme := web.Links("proxy.example.com", testSecret())
	assert.Equal(t, "tg://webproxy?server=proxy.example.com&secret=dd000102030405060708090a0b0c0d0e0f", tg)
	assert.Equal(t, "https://t.me/webproxy?server=proxy.example.com&secret=dd000102030405060708090a0b0c0d0e0f", tme)
}
