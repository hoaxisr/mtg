package config

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const tokenKeySize = 32

// TypeTokenKey is a 32-byte secret key given as base64 (standard or URL
// alphabet, padded or not). It never prints its value.
type TypeTokenKey struct {
	Value []byte
}

func (t *TypeTokenKey) Set(value string) error {
	// Normalise alphabets and padding, then decode as raw standard base64.
	normalized := strings.TrimRight(value, "=")
	normalized = strings.NewReplacer("-", "+", "_", "/").Replace(normalized)

	decoded, err := base64.RawStdEncoding.DecodeString(normalized)
	if err != nil {
		return fmt.Errorf("token key is not a valid base64 string: %w", err)
	}

	if len(decoded) != tokenKeySize {
		return fmt.Errorf("token key has to be exactly %d bytes, got %d",
			tokenKeySize, len(decoded))
	}

	t.Value = decoded

	return nil
}

func (t TypeTokenKey) Get(defaultValue []byte) []byte {
	if len(t.Value) == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeTokenKey) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeTokenKey) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// String returns a placeholder: the config is logged and the key must
// never reach logs.
func (t TypeTokenKey) String() string {
	if len(t.Value) == 0 {
		return ""
	}

	return "<redacted>"
}
