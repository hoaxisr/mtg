package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// NewPublicUpstream returns a handler that reverse-proxies public traffic to
// a local http upstream, keeping the incoming Host. The upstream gets
// X-Forwarded-For (the inbound value with the peer appended), and
// X-Forwarded-Host and X-Forwarded-Proto: the inbound values when the front
// proxy sent them, otherwise the inbound Host and scheme.
func NewPublicUpstream(target *url.URL) (http.Handler, error) {
	if target == nil || target.Scheme != "http" {
		return nil, errors.New("public upstream must use http scheme")
	}

	if target.User != nil || (target.Path != "" && target.Path != "/") ||
		target.RawQuery != "" || target.Fragment != "" {
		return nil, errors.New("public upstream must not have user, path, query or fragment")
	}

	addr, err := netip.ParseAddr(target.Hostname())
	if err != nil {
		return nil, fmt.Errorf("public upstream host must be an IP literal: %w", err)
	}

	if !addr.IsLoopback() && !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
		return nil, errors.New("public upstream must be loopback, private or link-local")
	}

	t := *target
	t.Path = ""

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&t)
			pr.Out.Host = pr.In.Host
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()

			// The listener sits behind a TLS-terminating front proxy, whose
			// X-Forwarded-Proto and X-Forwarded-Host are the truth.
			for _, k := range []string{"X-Forwarded-Proto", "X-Forwarded-Host"} {
				if v := pr.In.Header.Values(k); len(v) > 0 {
					pr.Out.Header[k] = v
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}, nil
}

type publicDir struct {
	dir string
}

// NewPublicDir serves static files from dir.
func NewPublicDir(dir string) (http.Handler, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot stat public dir: %w", err)
	}

	if !st.IsDir() {
		return nil, errors.New("public dir is not a directory")
	}

	return &publicDir{dir: dir}, nil
}

func (p *publicDir) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	if f, st := p.open(r.URL.Path); f != nil {
		defer func() { _ = f.Close() }()
		http.ServeContent(w, r, st.Name(), st.ModTime(), f)

		return
	}

	p.notFound(w, r)
}

// open returns a regular file for the url path, or nil.
func (p *publicDir) open(urlPath string) (*os.File, os.FileInfo) {
	if urlPath == "/" {
		urlPath = "/index.html"
	}

	if !strings.HasPrefix(urlPath, "/") || strings.HasSuffix(urlPath, "/") ||
		strings.Contains(urlPath, "\x00") {
		return nil, nil
	}

	for _, part := range strings.Split(urlPath, "/") {
		if part == ".." {
			return nil, nil
		}
	}

	clean := path.Clean(urlPath)

	f, err := os.Open(filepath.Join(p.dir, filepath.FromSlash(clean)))
	if err != nil {
		return nil, nil
	}

	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()

		return nil, nil
	}

	return f, st
}

func (p *publicDir) notFound(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(filepath.Join(p.dir, "404.html"))
	if err != nil {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)

		return
	}

	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)

	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, f)
	}
}
