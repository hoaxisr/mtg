package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
)

// TypeHTTPURL is a plain-HTTP URL of a local service. Its host has to be
// an IP literal that is loopback, private or link-local: such URLs point
// to a decoy server on the same machine or network, never to the internet.
type TypeHTTPURL struct {
	Value *url.URL
}

func (t *TypeHTTPURL) Set(value string) error {
	parsedURL, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("value is not correct URL (%s): %w", value, err)
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("url has to have a host: %s", value)
	}

	if parsedURL.Scheme != "http" {
		return fmt.Errorf("unsupported schema: %s", parsedURL.Scheme)
	}

	if parsedURL.User != nil {
		return fmt.Errorf("url must not contain userinfo: %s", value)
	}

	if parsedURL.Path != "" && parsedURL.Path != "/" {
		return fmt.Errorf("url must not contain a path: %s", value)
	}

	if parsedURL.RawQuery != "" || parsedURL.ForceQuery || parsedURL.Fragment != "" {
		return fmt.Errorf("url must not contain a query or a fragment: %s", value)
	}

	addr, err := netip.ParseAddr(parsedURL.Hostname())
	if err != nil {
		return fmt.Errorf("url host has to be an IP address: %s", value)
	}

	local := addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()

	if addr.Zone() != "" || !local {
		return fmt.Errorf("url host has to be loopback, private or link-local: %s", value)
	}

	if port := parsedURL.Port(); port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return fmt.Errorf("url port is incorrect: %s", value)
		}
	}

	parsedURL.Path = ""
	parsedURL.RawPath = ""
	t.Value = parsedURL

	return nil
}

func (t *TypeHTTPURL) Get(defaultValue *url.URL) *url.URL {
	if t.Value == nil {
		return defaultValue
	}

	return t.Value
}

func (t *TypeHTTPURL) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeHTTPURL) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeHTTPURL) String() string {
	if t.Value == nil {
		return ""
	}

	return t.Value.String()
}
