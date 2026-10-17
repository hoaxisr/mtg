package web

import "net/http"

// carrier is the per-mode HTTP handling of an established session. The
// handler authenticates the session token before calling into a carrier.
type carrier interface {
	// mode is the value of the X-Carrier-Mode header.
	mode() string
	handleUp(w http.ResponseWriter, r *http.Request, s *session)
	handleDown(w http.ResponseWriter, r *http.Request, s *session)
	handleWS(w http.ResponseWriter, r *http.Request, s *session)
}
