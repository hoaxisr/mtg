package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/9seconds/mtg/v2/mtglib"
)

const (
	webSecretPrefix  byte = 0xdd
	capabilityPrefix      = "tdesktop-web-proxy-bridge-v1\n"

	maxHostnameLength = 253
	maxLabelLength    = 63
)

// ErrHostname is returned when a hostname is not acceptable for WEB proxy.
var ErrHostname = errors.New("invalid hostname")

// Profile is a single secret served by WEB proxy.
type Profile struct {
	// Index is a position of the secret in mtglib.ProxyOpts.Secrets
	// (0 for a single secret).
	Index  int
	Secret mtglib.Secret
	// Limits are per-profile overrides; zero value = inherit the global Limits.
	Limits ProfileLimits
}

// ValidateHostname checks that h is a lowercase ASCII DNS name without a
// port, trailing dot or IP literal.
func ValidateHostname(h string) error {
	if h == "" || len(h) > maxHostnameLength {
		return fmt.Errorf("%w: bad length %d", ErrHostname, len(h))
	}

	if net.ParseIP(h) != nil {
		return fmt.Errorf("%w: %q is an IP literal", ErrHostname, h)
	}

	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > maxLabelLength {
			return fmt.Errorf("%w: bad label length in %q", ErrHostname, h)
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: label of %q starts or ends with '-'", ErrHostname, h)
		}

		for i := range len(label) {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("%w: bad character %q in %q", ErrHostname, c, h)
			}
		}
	}

	return nil
}

func webSecretBytes(s mtglib.Secret) []byte {
	return append([]byte{webSecretPrefix}, s.Key[:]...)
}

// WebSecret returns 'dd' + hex of a key: a secret as Telegram clients
// expect it for WEB proxy links.
func WebSecret(s mtglib.Secret) string {
	return hex.EncodeToString(webSecretBytes(s))
}

// Capability derives a capability token for a hostname.
func Capability(s mtglib.Secret, hostname string) string {
	mac := hmac.New(sha256.New, webSecretBytes(s))
	mac.Write([]byte(capabilityPrefix + hostname)) //nolint: errcheck

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Links returns tg:// and https://t.me links for a WEB proxy.
func Links(hostname string, s mtglib.Secret) (tgURL, tmeURL string) {
	query := "?server=" + url.QueryEscape(hostname) + "&secret=" + WebSecret(s)

	return "tg://webproxy" + query, "https://t.me/webproxy" + query
}
