package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type routeKind int

const (
	routePublic routeKind = iota
	routeBridge
	routeSessionCreate
	routeSessionDelete
	routeUp
	routeDown
	routeWS
	routeLocal404
)

var bridgeQueryRe = regexp.MustCompile(`^bridge=[A-Za-z0-9_-]{43}$`)

// classify decides how a request is handled. carriesSecret is computed by
// the scanner beforehand.
func classify(r *http.Request, hostname string, carriesSecret bool) routeKind {
	if !carriesSecret {
		return routePublic
	}

	host := strings.TrimSuffix(r.Host, ":443")
	if !strings.EqualFold(host, hostname) {
		return routeLocal404
	}

	var kind routeKind

	switch p := r.URL.Path; {
	case p == "/api/v1/session" && r.Method == http.MethodPost:
		kind = routeSessionCreate
	case p == "/api/v1/session" && r.Method == http.MethodDelete:
		kind = routeSessionDelete
	case p == "/api/v1/up" && r.Method == http.MethodPost:
		kind = routeUp
	case p == "/api/v1/down" && r.Method == http.MethodPost:
		kind = routeDown
	case p == "/api/v1/ws" && r.Method == http.MethodGet:
		kind = routeWS
	// The Cookie and duplicate-Authorization rejections below apply to API
	// endpoints only. The bridge is a browser navigation, and the
	// system-browser fallback may legitimately carry the public site's cookies.
	case p == "/" && r.Method == http.MethodGet && bridgeQueryRe.MatchString(r.URL.RawQuery):
		return routeBridge
	default:
		return routeLocal404
	}

	if r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path ||
		len(r.Header.Values("Authorization")) > 1 {
		return routeLocal404
	}

	if kind != routeWS && len(r.Header.Values("Cookie")) > 0 {
		return routeLocal404
	}

	return kind
}

// clientIP returns the address from X-Forwarded-For if the direct peer is a
// trusted front proxy.
func clientIP(r *http.Request, trusted []netip.Prefix) (net.IP, error) {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("bad remote addr: %w", err)
	}

	peer, err := netip.ParseAddr(h)
	if err != nil {
		return nil, fmt.Errorf("bad remote addr: %w", err)
	}

	peer = peer.Unmap()
	ok := false

	for _, p := range trusted {
		if p.Contains(peer) {
			ok = true

			break
		}
	}

	if !ok {
		return nil, errors.New("peer is not trusted")
	}

	vals := r.Header.Values("X-Forwarded-For")
	if len(vals) != 1 {
		return nil, errors.New("X-Forwarded-For must appear exactly once")
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(vals[0]))
	if err != nil {
		return nil, fmt.Errorf("bad X-Forwarded-For: %w", err)
	}

	return net.IP(addr.Unmap().AsSlice()), nil
}

// canonicalUint parses a plain decimal number without sign or leading zeros.
func canonicalUint(s string) (uint64, error) {
	if s == "" || len(s) > 20 {
		return 0, errors.New("bad number length")
	}

	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not a decimal number")
		}
	}

	if len(s) > 1 && s[0] == '0' {
		return 0, errors.New("leading zero")
	}

	return strconv.ParseUint(s, 10, 64)
}

func localNotFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNotFound)
}
