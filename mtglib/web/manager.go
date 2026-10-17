package web

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9seconds/mtg/v2/mtglib"
)

var (
	errNotFound = errors.New("web token is not found")
	errCapacity = errors.New("web proxy is at capacity")
)

// Stats is a snapshot of manager counters.
type Stats struct {
	SessionsLive, StreamsLive, BootstrapsLive int

	PendingBytes int64
	PendingItems int

	SessionsCreated, SessionsClosed, StreamsOpened, StreamsRejected, LimitHits, BytesUp, BytesDown uint64
}

type bootstrapEntry struct {
	profileIdx int
	ipKey      string
	created    time.Time

	// used is set once a session was created from this bootstrap. A used
	// bootstrap is kept until it expires so that a retried HELLO with the
	// identical body gets the same session token.
	used         bool
	helloDigest  [sha256.Size]byte
	sessionToken string
	sessionHash  tokenHash
}

type sessionEntry struct {
	s          *session
	token      string
	profileIdx int
	ipKey      string
}

type profileState struct {
	profile  *Profile
	limits   Limits
	sessions int
	streams  int

	sessionBucket *rateBucket
	streamBucket  *rateBucket
}

// manager owns all sessions and bootstraps and implements the global
// budgets (budgetSink). Lock order is session.mu -> manager.mu: the manager
// never calls into a session while holding its own mutex.
type manager struct {
	mu sync.Mutex

	limits   Limits
	timeouts Timeouts
	signer   *tokenSigner
	serve    serveFunc
	logger   mtglib.Logger
	// rootLogger is handed to sessions, which name their own logger.
	rootLogger mtglib.Logger
	now        func() time.Time

	profiles map[int]*profileState

	sessionBucket   *rateBucket
	streamBucket    *rateBucket
	bootstrapBucket *rateBucket

	bootstraps      map[tokenHash]*bootstrapEntry
	sessions        map[tokenHash]*sessionEntry
	closedTokens    map[tokenHash]time.Time
	sessionsPerIP   map[string]int
	bootstrapsPerIP map[string]int

	bootstrapsLive int
	streamsLive    int
	pendingBytes   int64
	pendingItems   int

	sessionsCreated uint64
	sessionsClosed  uint64
	streamsOpened   uint64
	streamsRejected uint64
	limitHits       uint64

	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64
}

func newManager(profiles []Profile, limits Limits, timeouts Timeouts, signer *tokenSigner,
	serve serveFunc, logger mtglib.Logger, now func() time.Time,
) (*manager, error) {
	// The global limits are validated once, by the handler's
	// validateOptions; only the per-profile merge is checked here.
	if signer == nil {
		return nil, errors.New("token signer is required")
	}

	if len(profiles) == 0 {
		return nil, errors.New("at least one profile is required")
	}

	start := now()
	m := &manager{
		limits:          limits,
		timeouts:        timeouts,
		signer:          signer,
		serve:           serve,
		logger:          logger.Named("web-manager"),
		rootLogger:      logger,
		now:             now,
		profiles:        make(map[int]*profileState, len(profiles)),
		sessionBucket:   newRateBucket(limits.NewSessionsPerMinute, limits.NewSessionsBurst, start),
		streamBucket:    newRateBucket(limits.NewStreamsPerMinute, limits.NewStreamsBurst, start),
		bootstrapBucket: newRateBucket(limits.NewBootstrapsPerMinute, limits.NewBootstrapsBurst, start),
		bootstraps:      map[tokenHash]*bootstrapEntry{},
		sessions:        map[tokenHash]*sessionEntry{},
		closedTokens:    map[tokenHash]time.Time{},
		sessionsPerIP:   map[string]int{},
		bootstrapsPerIP: map[string]int{},
	}

	for i := range profiles {
		p := profiles[i]
		if _, ok := m.profiles[p.Index]; ok {
			return nil, fmt.Errorf("duplicate profile index %d", p.Index)
		}

		merged := limits.merge(p.Limits)
		if err := merged.validateSessionBudget(); err != nil {
			return nil, fmt.Errorf("profile %d: %w", p.Index, err)
		}

		m.profiles[p.Index] = &profileState{
			profile:       &p,
			limits:        merged,
			sessionBucket: newRateBucket(merged.NewSessionsPerMinute, merged.NewSessionsBurst, start),
			streamBucket:  newRateBucket(merged.NewStreamsPerMinute, merged.NewStreamsBurst, start),
		}
	}

	return m, nil
}

func ipKey(ip net.IP) string {
	if ip == nil {
		return ""
	}

	return ip.String()
}

// giveBack returns a token taken from a bucket when a later check failed.
func giveBack(b *rateBucket) {
	b.tokens = min(b.burst, b.tokens+1)
}

// --- bootstraps and sessions -----------------------------------------------

func (m *manager) issueBootstrap(profileIdx int, ip net.IP) (string, error) {
	key := ipKey(ip)
	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.profiles[profileIdx]; !ok {
		return "", fmt.Errorf("unknown profile %d", profileIdx)
	}

	if m.bootstrapsLive >= m.limits.MaxBootstraps ||
		(m.limits.MaxBootstrapsPerIP > 0 && m.bootstrapsPerIP[key] >= m.limits.MaxBootstrapsPerIP) ||
		!m.bootstrapBucket.take(now) {
		m.limitHits++

		return "", errCapacity
	}

	token, hash, err := m.signer.issue(tokenBootstrap)
	if err != nil {
		giveBack(m.bootstrapBucket)

		return "", fmt.Errorf("cannot issue bootstrap token: %w", err)
	}

	m.bootstraps[hash] = &bootstrapEntry{
		profileIdx: profileIdx,
		ipKey:      key,
		created:    now,
	}
	m.bootstrapsLive++
	m.bootstrapsPerIP[key]++

	return token, nil
}

func (m *manager) createSession(bootstrap string, hello []byte, ip net.IP) (string, *session, error) {
	hash, ok := m.signer.verifyBearer(bootstrap, tokenBootstrap)
	if !ok {
		return "", nil, errNotFound
	}

	key := ipKey(ip)
	digest := sha256.Sum256(hello)
	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.bootstraps[hash]
	if entry == nil {
		return "", nil, errNotFound
	}

	if now.Sub(entry.created) > m.timeouts.BootstrapLifetime {
		m.removeBootstrapLocked(hash, entry)

		return "", nil, errNotFound
	}

	if entry.used {
		if entry.helloDigest != digest {
			return "", nil, errNotFound
		}

		se := m.sessions[entry.sessionHash]
		if se == nil || isSessionClosed(se.s) {
			return "", nil, errNotFound
		}

		return entry.sessionToken, se.s, nil
	}

	ps := m.profiles[entry.profileIdx]
	if !m.admitSessionLocked(ps, key, now) {
		m.limitHits++

		return "", nil, errCapacity
	}

	token, sessHash, err := m.signer.issue(tokenSession)
	if err != nil {
		giveBack(m.sessionBucket)
		giveBack(ps.sessionBucket)

		return "", nil, fmt.Errorf("cannot issue session token: %w", err)
	}

	s := newSession(ps.profile, ps.limits, m, m.serve, ip, m.rootLogger, m.now)

	m.sessions[sessHash] = &sessionEntry{
		s:          s,
		token:      token,
		profileIdx: entry.profileIdx,
		ipKey:      key,
	}
	m.sessionsPerIP[key]++
	ps.sessions++
	m.sessionsCreated++

	entry.used = true
	entry.helloDigest = digest
	entry.sessionToken = token
	entry.sessionHash = sessHash
	m.bootstrapsLive--
	m.decIP(m.bootstrapsPerIP, entry.ipKey)

	return token, s, nil
}

// admitSessionLocked checks global, per-profile and per-IP session caps and
// takes a token from both rate buckets.
func (m *manager) admitSessionLocked(ps *profileState, key string, now time.Time) bool {
	if len(m.sessions) >= m.limits.MaxSessions || ps.sessions >= ps.limits.MaxSessions {
		return false
	}

	if m.limits.MaxSessionsPerIP > 0 && m.sessionsPerIP[key] >= m.limits.MaxSessionsPerIP {
		return false
	}

	if !m.sessionBucket.take(now) {
		return false
	}

	if !ps.sessionBucket.take(now) {
		giveBack(m.sessionBucket)

		return false
	}

	return true
}

func (m *manager) lookupSession(token string) (*session, bool) {
	hash, ok := m.signer.verifyBearer(token, tokenSession)
	if !ok {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	se := m.sessions[hash]
	if se == nil {
		return nil, false
	}

	if isSessionClosed(se.s) {
		m.forgetSessionLocked(hash, se, m.now())

		return nil, false
	}

	return se.s, true
}

// deleteSession closes a session; true if it was live or recently closed.
func (m *manager) deleteSession(token string) bool {
	hash, ok := m.signer.verifyBearer(token, tokenSession)
	if !ok {
		return false
	}

	m.mu.Lock()

	se := m.sessions[hash]
	if se == nil {
		_, recent := m.closedTokens[hash]
		m.mu.Unlock()

		return recent
	}

	m.forgetSessionLocked(hash, se, m.now())
	m.mu.Unlock()

	se.s.close()

	return true
}

// cleanup expires bootstraps and closed-token memory older than
// BootstrapLifetime and closes sessions idle longer than ReconnectGrace.
func (m *manager) cleanup(now time.Time) {
	m.mu.Lock()

	for hash, entry := range m.bootstraps {
		if now.Sub(entry.created) > m.timeouts.BootstrapLifetime {
			m.removeBootstrapLocked(hash, entry)
		}
	}

	for hash, closedAt := range m.closedTokens {
		if now.Sub(closedAt) > m.timeouts.BootstrapLifetime {
			delete(m.closedTokens, hash)
		}
	}

	candidates := make(map[tokenHash]*session, len(m.sessions))
	for hash, se := range m.sessions {
		candidates[hash] = se.s
	}

	m.mu.Unlock()

	// lastActivity takes the session lock: never under m.mu.
	var expired []tokenHash

	for hash, s := range candidates {
		if isSessionClosed(s) || now.Sub(s.lastActivity()) > m.timeouts.ReconnectGrace {
			expired = append(expired, hash)
		}
	}

	if len(expired) == 0 {
		return
	}

	toClose := make([]*session, 0, len(expired))

	m.mu.Lock()

	for _, hash := range expired {
		if se := m.sessions[hash]; se != nil && se.s == candidates[hash] {
			m.forgetSessionLocked(hash, se, now)
			toClose = append(toClose, se.s)
		}
	}

	m.mu.Unlock()

	for _, s := range toClose {
		s.close()
	}

	if len(toClose) > 0 {
		m.logger.BindInt("count", len(toClose)).Debug("expired idle sessions")
	}
}

func (m *manager) closeAll() {
	m.closeAllSessions()
}

// closeAllSessions closes every live session and returns them, so that the
// caller can wait for their pumps.
func (m *manager) closeAllSessions() []*session {
	m.mu.Lock()

	now := m.now()
	toClose := make([]*session, 0, len(m.sessions))

	for hash, se := range m.sessions {
		m.forgetSessionLocked(hash, se, now)
		toClose = append(toClose, se.s)
	}

	m.mu.Unlock()

	for _, s := range toClose {
		s.close()
	}

	return toClose
}

func (m *manager) stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()

	return Stats{
		SessionsLive:    len(m.sessions),
		StreamsLive:     m.streamsLive,
		BootstrapsLive:  m.bootstrapsLive,
		PendingBytes:    m.pendingBytes,
		PendingItems:    m.pendingItems,
		SessionsCreated: m.sessionsCreated,
		SessionsClosed:  m.sessionsClosed,
		StreamsOpened:   m.streamsOpened,
		StreamsRejected: m.streamsRejected,
		LimitHits:       m.limitHits,
		BytesUp:         m.bytesUp.Load(),
		BytesDown:       m.bytesDown.Load(),
	}
}

// addBytes accounts body bytes received from (up) and sent to (down) clients.
func (m *manager) addBytes(up, down uint64) {
	m.bytesUp.Add(up)
	m.bytesDown.Add(down)
}

func (m *manager) removeBootstrapLocked(hash tokenHash, entry *bootstrapEntry) {
	delete(m.bootstraps, hash)

	if !entry.used {
		m.bootstrapsLive--
		m.decIP(m.bootstrapsPerIP, entry.ipKey)
	}
}

// forgetSessionLocked removes a session from the maps (the caller closes
// it after releasing m.mu) and remembers its token as recently closed.
func (m *manager) forgetSessionLocked(hash tokenHash, se *sessionEntry, now time.Time) {
	delete(m.sessions, hash)
	m.closedTokens[hash] = now
	m.decIP(m.sessionsPerIP, se.ipKey)
	m.profiles[se.profileIdx].sessions--
	m.sessionsClosed++
}

func (m *manager) decIP(counts map[string]int, key string) {
	if counts[key] <= 1 {
		delete(counts, key)
	} else {
		counts[key]--
	}
}

func isSessionClosed(s *session) bool {
	select {
	case <-s.closed():
		return true
	default:
		return false
	}
}

// --- budgetSink --------------------------------------------------------------

func (m *manager) changePending(class pendingClass, bytes int64, items int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if bytes > 0 || items > 0 {
		maxBytes := m.limits.MaxPendingGlobal
		maxItems := m.limits.MaxPendingItemsGlobal

		if class != pendingControl {
			maxBytes -= m.limits.controlReserveBytes() * int64(m.limits.MaxSessions)
			maxItems -= m.limits.controlReserveItems() * m.limits.MaxSessions
		}

		if m.pendingBytes+bytes > maxBytes || m.pendingItems+items > maxItems {
			m.limitHits++

			return false
		}
	}

	m.pendingBytes += bytes
	m.pendingItems += items

	return true
}

func (m *manager) acquireStream(profileIdx int, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	ps := m.profiles[profileIdx]
	if ps == nil {
		m.streamsRejected++

		return false
	}

	if m.streamsLive >= m.limits.MaxStreams || ps.streams >= ps.limits.MaxStreams ||
		!m.streamBucket.take(now) {
		m.streamsRejected++
		m.limitHits++

		return false
	}

	if !ps.streamBucket.take(now) {
		giveBack(m.streamBucket)
		m.streamsRejected++
		m.limitHits++

		return false
	}

	m.streamsLive++
	ps.streams++
	m.streamsOpened++

	return true
}

func (m *manager) releaseStream(profileIdx int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ps := m.profiles[profileIdx]; ps != nil && ps.streams > 0 {
		ps.streams--
		m.streamsLive--
	}
}
