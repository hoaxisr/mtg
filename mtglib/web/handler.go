package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/logger"
	"github.com/9seconds/mtg/v2/mtglib"
)

const (
	// maxHelloBytes caps the body of a session create request.
	maxHelloBytes = 64
	// cleanupInterval is how often bootstraps and idle sessions expire.
	cleanupInterval = 30 * time.Second

	// bodyReadTimeout bounds reading the body of an authenticated request:
	// the protocol keeps bodies under the carrier read deadline, so a
	// secret holder cannot trickle a body and hold a request forever.
	bodyReadTimeout = 30 * time.Second
	// bodyWriteTimeout bounds writing a downlink response body: a reader
	// that stops consuming cannot hold the session's downlink write slot
	// and the body's memory longer than this.
	bodyWriteTimeout = 30 * time.Second

	bridgeQueryPrefix = "bridge="
	bearerPrefix      = "Bearer "
)

// ErrOptions is returned by NewHandler when Options are not acceptable.
var ErrOptions = errors.New("invalid web proxy options")

// Options configure a WEB proxy Handler.
type Options struct {
	// Hostname is the public DNS name of the proxy (lowercase, no port).
	Hostname string
	// Profiles are the secrets served by WEB proxy. Indexes and keys must be
	// unique.
	Profiles []Profile
	// Serve hands a stream to mtglib, usually (*mtglib.Proxy).ServeWebConn.
	Serve func(conn essentials.Conn, secretIdx int) error
	// Public answers every request that carries no authentic secret.
	Public http.Handler
	// TrustedProxies are the peers allowed to set X-Forwarded-For. nil or
	// empty means loopback only (127.0.0.0/8 and ::1/128). An explicit
	// "trust nothing" cannot be expressed, and is not needed: the handler
	// always runs behind a reverse proxy, which must be trusted.
	TrustedProxies []netip.Prefix
	// TokenKey signs bootstrap and session tokens: nil derives it from the
	// first profile's secret, otherwise it must be exactly 32 bytes.
	// Multi-tenant embedders should set an explicit key: with the default,
	// whoever knows Profiles[0]'s secret can derive the signing key.
	TokenKey []byte
	// Limits; the zero value means DefaultLimits().
	Limits Limits
	// Timeouts; every zero field takes its DefaultTimeouts() value.
	Timeouts Timeouts
	// Logger; nil means no logging.
	Logger mtglib.Logger
}

type profileCapability struct {
	index int
	value []byte
}

// Handler is an http.Handler serving WEB proxy clients and, for everybody
// else, the public site.
type Handler struct {
	hostname     string
	public       http.Handler
	trusted      []netip.Prefix
	limits       Limits
	timeouts     Timeouts
	logger       mtglib.Logger
	signer       *tokenSigner
	scanner      *secretScanner
	manager      *manager
	carrier      *httpsCarrier
	capabilities []profileCapability
	now          func() time.Time

	// mu guards closed, the inflight.Add calls and tracked.
	mu       sync.Mutex
	closed   bool
	inflight sync.WaitGroup
	tracked  map[*session]struct{}
	// sessions counts tracked sessions whose pumps are still running.
	sessions sync.WaitGroup

	stopCleanup  chan struct{}
	shutdownOnce sync.Once
	drained      chan struct{}
}

// NewHandler validates options and builds a Handler. It starts a background
// cleanup loop which runs until Shutdown.
func NewHandler(opts Options) (*Handler, error) {
	if err := validateOptions(&opts); err != nil {
		return nil, err
	}

	key := opts.TokenKey
	if key == nil {
		key = deriveTokenKey(opts.Profiles[0].Secret.Key[:])
	}

	signer, err := newTokenSigner(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOptions, err)
	}

	h := &Handler{
		hostname:    opts.Hostname,
		public:      opts.Public,
		trusted:     opts.TrustedProxies,
		limits:      opts.Limits,
		timeouts:    opts.Timeouts,
		logger:      opts.Logger.Named("web"),
		signer:      signer,
		carrier:     newHTTPSCarrier(opts.Limits, opts.Timeouts),
		now:         time.Now,
		tracked:     map[*session]struct{}{},
		stopCleanup: make(chan struct{}),
		drained:     make(chan struct{}),
	}

	capabilities := make([]string, 0, len(opts.Profiles))

	for _, p := range opts.Profiles {
		c := Capability(p.Secret, opts.Hostname)
		capabilities = append(capabilities, c)
		h.capabilities = append(h.capabilities, profileCapability{index: p.Index, value: []byte(c)})
	}

	h.scanner = newSecretScanner(signer, capabilities)

	h.manager, err = newManager(opts.Profiles, opts.Limits, opts.Timeouts, signer,
		opts.Serve, opts.Logger, h.now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOptions, err)
	}

	h.carrier.onBytes = h.manager.addBytes

	go h.cleanupLoop()

	return h, nil
}

func validateOptions(opts *Options) error {
	if err := ValidateHostname(opts.Hostname); err != nil {
		return fmt.Errorf("%w: %w", ErrOptions, err)
	}

	if len(opts.Profiles) == 0 {
		return fmt.Errorf("%w: at least one profile is required", ErrOptions)
	}

	indexes := make(map[int]struct{}, len(opts.Profiles))
	keys := make(map[[mtglib.SecretKeyLength]byte]struct{}, len(opts.Profiles))

	for i, p := range opts.Profiles {
		if !p.Secret.Valid() {
			return fmt.Errorf("%w: profile %d has an invalid secret", ErrOptions, i)
		}

		if p.Index < 0 {
			return fmt.Errorf("%w: profile %d has a negative index", ErrOptions, i)
		}

		if _, ok := indexes[p.Index]; ok {
			return fmt.Errorf("%w: duplicate profile index %d", ErrOptions, p.Index)
		}

		if _, ok := keys[p.Secret.Key]; ok {
			return fmt.Errorf("%w: profile %d duplicates a secret key", ErrOptions, i)
		}

		indexes[p.Index] = struct{}{}
		keys[p.Secret.Key] = struct{}{}
	}

	if opts.Serve == nil {
		return fmt.Errorf("%w: Serve is required", ErrOptions)
	}

	if opts.Public == nil {
		return fmt.Errorf("%w: Public is required", ErrOptions)
	}

	if opts.TokenKey != nil && len(opts.TokenKey) != tokenKeySize {
		return fmt.Errorf("%w: token key must be %d bytes", ErrOptions, tokenKeySize)
	}

	if len(opts.TrustedProxies) == 0 {
		opts.TrustedProxies = []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		}
	}

	if opts.Limits == (Limits{}) {
		opts.Limits = DefaultLimits()
	}

	if err := opts.Limits.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrOptions, err)
	}

	if err := applyTimeoutDefaults(&opts.Timeouts); err != nil {
		return err
	}

	if opts.Logger == nil {
		opts.Logger = logger.NewNoopLogger()
	}

	return nil
}

func applyTimeoutDefaults(t *Timeouts) error {
	if err := ValidateTimeouts(*t); err != nil {
		return fmt.Errorf("%w: %w", ErrOptions, err)
	}

	*t = t.withDefaults()

	return nil
}

// Capability returns the bridge capability of the profile with the given
// Index ("" if there is no such profile).
func (h *Handler) Capability(profileIdx int) string {
	for _, c := range h.capabilities {
		if c.index == profileIdx {
			return string(c.value)
		}
	}

	return ""
}

// Stats returns a snapshot of the handler counters.
func (h *Handler) Stats() Stats {
	return h.manager.stats()
}

// ServeHTTP routes a request: requests without an authentic capability or
// token go to the public handler untouched; everything else is handled
// locally.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	kind := classify(r, h.hostname, h.scanner.requestCarriesSecret(r))
	if kind == routePublic {
		h.public.ServeHTTP(w, r)

		return
	}

	w.Header().Set("Cache-Control", "no-store")

	if !h.enter() {
		localNotFound(w)

		return
	}

	defer h.inflight.Done()

	ip, err := clientIP(r, h.trusted)
	if err != nil {
		h.logger.Debug("authenticated request without an acceptable client ip")
		localNotFound(w)

		return
	}

	switch kind { //nolint: exhaustive
	case routeBridge:
		h.serveBridge(w, r, ip)
	case routeSessionCreate:
		h.serveSessionCreate(w, r, ip)
	case routeSessionDelete:
		h.serveSessionDelete(w, r)
	case routeUp, routeDown, routeWS:
		h.serveCarrier(w, r, kind)
	default:
		localNotFound(w)
	}
}

// enter registers an in-flight authenticated request; false after Shutdown.
func (h *Handler) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return false
	}

	h.inflight.Add(1)

	return true
}

func (h *Handler) serveBridge(w http.ResponseWriter, r *http.Request, ip net.IP) {
	value := []byte(strings.TrimPrefix(r.URL.RawQuery, bridgeQueryPrefix))
	profileIdx, found := -1, false

	// Every capability is compared, in constant time.
	for _, c := range h.capabilities {
		if subtle.ConstantTimeCompare(value, c.value) == 1 {
			profileIdx, found = c.index, true
		}
	}

	if !found {
		localNotFound(w)

		return
	}

	bootstrap, err := h.manager.issueBootstrap(profileIdx, ip)
	if err != nil {
		if !errors.Is(err, errCapacity) {
			h.logger.WarningError("cannot issue bootstrap", err)
		}

		localNotFound(w)

		return
	}

	page, err := renderBridge(h.hostname, bootstrap, h.limits.CarrierBatchBytes,
		int(h.timeouts.LongPoll/time.Millisecond))
	if err != nil {
		h.logger.WarningError("cannot render bridge page", err)
		localNotFound(w)

		return
	}

	writeBridge(w, page)
}

func (h *Handler) serveSessionCreate(w http.ResponseWriter, r *http.Request, ip net.IP) {
	bootstrap, ok := bearerToken(r)
	if !ok {
		localNotFound(w)

		return
	}

	if _, ok := h.signer.verifyBearer(bootstrap, tokenBootstrap); !ok {
		localNotFound(w)

		return
	}

	if ct := r.Header.Values("Content-Type"); len(ct) != 1 || ct[0] != octetStream {
		localNotFound(w)

		return
	}

	if !armBodyDeadline(w) {
		localNotFound(w)

		return
	}

	hello, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHelloBytes))

	disarmBodyDeadline(w)

	if err != nil || ParseHello(hello) != nil {
		localNotFound(w)

		return
	}

	token, s, err := h.manager.createSession(bootstrap, hello, ip)

	switch {
	case errors.Is(err, errCapacity):
		hdr := w.Header()
		hdr.Set("Retry-After", "1")
		hdr.Set("Content-Length", "0")
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	case errors.Is(err, errNotFound):
		localNotFound(w)

		return
	case err != nil:
		h.logger.WarningError("cannot create session", err)
		localNotFound(w)

		return
	}

	h.track(s)

	welcome := EncodeFrame(FrameWelcome, 0, nil)
	hdr := w.Header()
	hdr.Set("Content-Type", octetStream)
	hdr.Set("Content-Length", strconv.Itoa(len(welcome)))
	hdr.Set("X-Session-Token", token)
	hdr.Set("X-Down-Cursor", "0")
	hdr.Set("X-Carrier-Mode", h.carrier.mode())
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(welcome); err != nil {
		return
	}

	h.manager.addBytes(uint64(len(hello)), uint64(len(welcome)))
}

func (h *Handler) serveSessionDelete(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok || len(r.Header.Values("Content-Type")) != 0 || r.ContentLength > 0 || !emptyBodyBounded(w, r) {
		localNotFound(w)

		return
	}

	if !h.manager.deleteSession(token) {
		localNotFound(w)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveCarrier(w http.ResponseWriter, r *http.Request, kind routeKind) {
	token, ok := bearerToken(r)
	if !ok {
		localNotFound(w)

		return
	}

	s, ok := h.manager.lookupSession(token)
	if !ok {
		localNotFound(w)

		return
	}

	switch kind { //nolint: exhaustive
	case routeUp:
		h.carrier.handleUp(w, r, s)
	case routeDown:
		h.carrier.handleDown(w, r, s)
	default:
		h.carrier.handleWS(w, r, s)
	}

	// A protocol violation closed the session: release its admission slot
	// now instead of at the next cleanup.
	if isSessionClosed(s) {
		h.manager.deleteSession(token)
	}
}

// armBodyDeadline sets the read deadline for the request body. A writer
// that cannot set deadlines (http.ErrNotSupported, e.g. some test servers)
// is accepted; any other error means the request must be refused.
func armBodyDeadline(w http.ResponseWriter) bool {
	err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadTimeout))

	return err == nil || errors.Is(err, http.ErrNotSupported)
}

// disarmBodyDeadline clears the body read deadline once the body is read.
// It must not outlive the body: net/http keeps reading the connection in
// the background to notice a client that went away, and a deadline firing
// there would cancel the request context (e.g. of a long poll).
func disarmBodyDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
}

// emptyBodyBounded is emptyBody under the body read deadline.
func emptyBodyBounded(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}

	if !armBodyDeadline(w) {
		return false
	}

	defer disarmBodyDeadline(w)

	return emptyBody(r.Body)
}

// bearerToken returns the token of the single Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}

	return strings.CutPrefix(values[0], bearerPrefix)
}

// track remembers a new session so that Shutdown can wait for its pumps.
func (h *Handler) track(s *session) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.tracked[s]; ok {
		return // a replayed create returns the same session
	}

	h.tracked[s] = struct{}{}
	h.sessions.Add(1)

	go func() {
		defer h.sessions.Done()

		<-s.closed()
		s.wait()

		h.mu.Lock()
		delete(h.tracked, s)
		h.mu.Unlock()
	}()
}

func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCleanup:
			return
		case <-ticker.C:
			h.manager.cleanup(h.now())
		}
	}
}

// Shutdown stops accepting authenticated requests (the public site keeps
// being served), stops the cleanup loop, closes every session and waits for
// in-flight requests and session pumps until ctx is done. It may be called
// again to keep waiting.
func (h *Handler) Shutdown(ctx context.Context) error {
	h.shutdownOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()

		close(h.stopCleanup)

		// Closing sessions releases parked polls.
		h.manager.closeAll()

		go func() {
			h.inflight.Wait()
			// A request in flight could have created a session meanwhile.
			h.manager.closeAll()
			// No request is in flight and none can start: track is not
			// called anymore.
			h.sessions.Wait()
			close(h.drained)
		}()

		h.logger.Info("shutting down")
	})

	select {
	case <-h.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err() //nolint: wrapcheck
	}
}
