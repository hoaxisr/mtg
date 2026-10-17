package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const (
	tokenRawSize     = 32
	tokenEncodedSize = 43
	tokenNonceSize   = 12
	tokenTagSize     = 4
	tokenMACSize     = 16
	tokenKeySize     = 32

	tokenFilterBlockSize = aes.BlockSize

	tokenKeyLabel    = "mtg-web-token-key-v1"
	tokenMACLabel    = "tproxy-server-token-v1\x00"
	tokenFilterLabel = "tproxy-server-token-filter-v1\x00"
)

type tokenKind byte

const (
	tokenBootstrap tokenKind = 1
	tokenSession   tokenKind = 2
)

// tokenHash is sha256 of 32 raw token bytes. It is used as a map key.
type tokenHash [32]byte

type tokenSigner struct {
	macKey []byte
	filter cipher.Block
}

func deriveTokenKey(secretKey []byte) []byte {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(tokenKeyLabel)) //nolint: errcheck

	return mac.Sum(nil)
}

func newTokenSigner(key []byte) (*tokenSigner, error) {
	if len(key) != tokenKeySize {
		return nil, fmt.Errorf("token key must be %d bytes, got %d", tokenKeySize, len(key))
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(tokenFilterLabel)) //nolint: errcheck

	block, err := aes.NewCipher(mac.Sum(nil)[:16])
	if err != nil {
		return nil, fmt.Errorf("cannot init filter cipher: %w", err)
	}

	return &tokenSigner{
		macKey: append([]byte(nil), key...),
		filter: block,
	}, nil
}

// tag returns a 4-byte filter tag of a nonce.
func (s *tokenSigner) tag(nonce []byte) []byte {
	var in, out [aes.BlockSize]byte

	copy(in[:], nonce[:tokenNonceSize])
	s.filter.Encrypt(out[:], in[:])

	return out[:tokenTagSize]
}

// tagMatches reports whether raw carries the filter tag of its nonce, like
// classify does first, but without allocating: scratch must hold at least
// 2*tokenFilterBlockSize bytes.
func (s *tokenSigner) tagMatches(raw, scratch []byte) bool {
	in := scratch[:tokenFilterBlockSize]
	out := scratch[tokenFilterBlockSize : 2*tokenFilterBlockSize]

	clear(in)
	copy(in, raw[:tokenNonceSize])
	s.filter.Encrypt(out, in)

	return subtle.ConstantTimeCompare(out[:tokenTagSize], raw[tokenNonceSize:tokenNonceSize+tokenTagSize]) == 1
}

func (s *tokenSigner) mac(kind tokenKind, prefix []byte) []byte {
	mac := hmac.New(sha256.New, s.macKey)
	mac.Write([]byte(tokenMACLabel)) //nolint: errcheck
	mac.Write([]byte{byte(kind)})    //nolint: errcheck
	mac.Write(prefix)                //nolint: errcheck

	return mac.Sum(nil)[:tokenMACSize]
}

func (s *tokenSigner) issue(kind tokenKind) (string, tokenHash, error) {
	raw := make([]byte, tokenRawSize)

	if _, err := rand.Read(raw[:tokenNonceSize]); err != nil {
		return "", tokenHash{}, fmt.Errorf("cannot generate nonce: %w", err)
	}

	copy(raw[tokenNonceSize:], s.tag(raw))
	copy(raw[16:], s.mac(kind, raw[:16]))

	return base64.RawURLEncoding.EncodeToString(raw), sha256.Sum256(raw), nil
}

func (s *tokenSigner) macValid(kind tokenKind, raw []byte) bool {
	return subtle.ConstantTimeCompare(s.mac(kind, raw[:16]), raw[16:]) == 1
}

func (s *tokenSigner) verifyBearer(encoded string, kind tokenKind) (tokenHash, bool) {
	if len(encoded) != tokenEncodedSize {
		return tokenHash{}, false
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != tokenRawSize {
		return tokenHash{}, false
	}

	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return tokenHash{}, false
	}

	if !s.macValid(kind, raw) {
		return tokenHash{}, false
	}

	return sha256.Sum256(raw), true
}

func (s *tokenSigner) classify(raw []byte) (tokenKind, tokenHash, bool) {
	if len(raw) != tokenRawSize {
		return 0, tokenHash{}, false
	}

	if subtle.ConstantTimeCompare(s.tag(raw), raw[tokenNonceSize:16]) != 1 {
		return 0, tokenHash{}, false
	}

	for _, kind := range []tokenKind{tokenBootstrap, tokenSession} {
		if s.macValid(kind, raw) {
			return kind, sha256.Sum256(raw), true
		}
	}

	return 0, tokenHash{}, false
}
