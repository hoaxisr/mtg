package web

import (
	"errors"
	"fmt"
	"time"
)

const (
	// queueItemCost is a fixed accounting overhead of a queued item.
	queueItemCost = 256

	minCarrierBatchBytes = 256 << 10
	maxCarrierBatchBytes = 2 << 20
	maxFramePayloadLimit = 1 << 20

	// maxCount caps every count field so that no intermediate product can
	// overflow, including on 32-bit builds.
	maxCount = 1 << 30
	// maxStreamsPerSessionLimit is lower because controlReserveItems
	// multiplies it by 3 in int.
	maxStreamsPerSessionLimit = 1 << 20
	maxBytesLimit             = 1 << 50

	// minDownlinkBytes is the smallest downlink share of a per-session
	// budget: what is left of MaxPendingPerSession after the control and
	// uplink reserves.
	minDownlinkBytes = 1 << 20
)

// ErrLimits is returned when Limits are inconsistent.
var ErrLimits = errors.New("invalid web limits")

// Limits are global resource limits of WEB proxy.
type Limits struct {
	MaxSessions          int
	MaxSessionsPerIP     int
	MaxStreams           int
	MaxStreamsPerSession int

	NewSessionsPerMinute int
	NewSessionsBurst     int
	NewStreamsPerMinute  int
	NewStreamsBurst      int

	MaxBootstraps          int
	MaxBootstrapsPerIP     int
	NewBootstrapsPerMinute int
	NewBootstrapsBurst     int

	MaxPendingPerSession int64
	MaxPendingGlobal     int64

	MaxPendingItemsPerSession int
	MaxPendingItemsGlobal     int

	// CarrierBatchBytes caps one downlink response body. A session writes
	// at most one downlink body at a time, under a write deadline, so
	// in-flight download memory is bounded by MaxSessions ×
	// CarrierBatchBytes.
	CarrierBatchBytes int
	// MaxBodyBytes caps one uplink request body. A session reads at most
	// one uplink body at a time, so in-flight upload memory is bounded by
	// MaxSessions × MaxBodyBytes (a session create reads only a hello of
	// at most maxHelloBytes).
	MaxBodyBytes       int
	MaxFramePayload    int
	MaxClosedStreamIDs int
}

// DefaultLimits returns the default limits.
func DefaultLimits() Limits {
	return Limits{
		MaxSessions:          128,
		MaxSessionsPerIP:     0,
		MaxStreams:           4096,
		MaxStreamsPerSession: 128,

		NewSessionsPerMinute: 600,
		NewSessionsBurst:     128,
		NewStreamsPerMinute:  6000,
		NewStreamsBurst:      512,

		MaxBootstraps:          512,
		MaxBootstrapsPerIP:     0,
		NewBootstrapsPerMinute: 1200,
		NewBootstrapsBurst:     256,

		MaxPendingPerSession: 32 << 20,
		MaxPendingGlobal:     512 << 20,

		MaxPendingItemsPerSession: 16384,
		MaxPendingItemsGlobal:     262144,

		CarrierBatchBytes:  2 << 20,
		MaxBodyBytes:       2 << 20,
		MaxFramePayload:    1 << 20,
		MaxClosedStreamIDs: 4096,
	}
}

// ProfileLimits are per-profile overrides. Zero means "inherit global";
// values may only lower the global limit.
type ProfileLimits struct {
	MaxSessions          int
	MaxStreams           int
	MaxStreamsPerSession int

	NewSessionsPerMinute int
	NewSessionsBurst     int
	NewStreamsPerMinute  int
	NewStreamsBurst      int

	MaxPendingPerSession int64
}

// Timeouts are time-related settings of WEB proxy.
type Timeouts struct {
	LongPoll          time.Duration
	ReconnectGrace    time.Duration
	BootstrapLifetime time.Duration
	Shutdown          time.Duration
}

// DefaultTimeouts returns the default timeouts.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		LongPoll:          25 * time.Second,
		ReconnectGrace:    2 * time.Minute,
		BootstrapLifetime: 2 * time.Minute,
		Shutdown:          15 * time.Second,
	}
}

func (l Limits) controlReserveItems() int {
	return 16 + 3*l.MaxStreamsPerSession
}

func (l Limits) controlReserveBytes() int64 {
	return int64(l.controlReserveItems()) * (queueItemCost + FrameHeaderSize + 4)
}

// uplinkReserveItems is how many items one uplink body can queue at most.
func (l Limits) uplinkReserveItems() int {
	return min(l.MaxBodyBytes/8, MaxBatchFrames)
}

func (l Limits) uplinkReserveBytes() int64 {
	return int64(l.MaxBodyBytes) + int64(l.uplinkReserveItems())*queueItemCost
}

func (l Limits) validate() error {
	positive := []struct {
		name  string
		value int64
		max   int64
	}{
		{"MaxSessions", int64(l.MaxSessions), maxCount},
		{"MaxStreams", int64(l.MaxStreams), maxCount},
		{"MaxStreamsPerSession", int64(l.MaxStreamsPerSession), maxStreamsPerSessionLimit},
		{"NewSessionsPerMinute", int64(l.NewSessionsPerMinute), maxCount},
		{"NewSessionsBurst", int64(l.NewSessionsBurst), maxCount},
		{"NewStreamsPerMinute", int64(l.NewStreamsPerMinute), maxCount},
		{"NewStreamsBurst", int64(l.NewStreamsBurst), maxCount},
		{"MaxBootstraps", int64(l.MaxBootstraps), maxCount},
		{"NewBootstrapsPerMinute", int64(l.NewBootstrapsPerMinute), maxCount},
		{"NewBootstrapsBurst", int64(l.NewBootstrapsBurst), maxCount},
		{"MaxPendingPerSession", l.MaxPendingPerSession, maxBytesLimit},
		{"MaxPendingGlobal", l.MaxPendingGlobal, maxBytesLimit},
		{"MaxPendingItemsPerSession", int64(l.MaxPendingItemsPerSession), maxCount},
		{"MaxPendingItemsGlobal", int64(l.MaxPendingItemsGlobal), maxCount},
		{"MaxBodyBytes", int64(l.MaxBodyBytes), maxCount},
		{"MaxClosedStreamIDs", int64(l.MaxClosedStreamIDs), maxCount},
	}
	for _, p := range positive {
		if p.value <= 0 {
			return fmt.Errorf("%w: %s must be positive, got %d", ErrLimits, p.name, p.value)
		}

		if p.value > p.max {
			return fmt.Errorf("%w: %s %d exceeds maximum %d", ErrLimits, p.name, p.value, p.max)
		}
	}

	if l.MaxSessionsPerIP < 0 || l.MaxSessionsPerIP > maxCount {
		return fmt.Errorf("%w: MaxSessionsPerIP %d is out of [0, %d]", ErrLimits, l.MaxSessionsPerIP, maxCount)
	}

	if l.MaxBootstrapsPerIP < 0 || l.MaxBootstrapsPerIP > maxCount {
		return fmt.Errorf("%w: MaxBootstrapsPerIP %d is out of [0, %d]", ErrLimits, l.MaxBootstrapsPerIP, maxCount)
	}

	maxBatch := min(l.MaxBodyBytes, maxCarrierBatchBytes)
	if l.CarrierBatchBytes < minCarrierBatchBytes || l.CarrierBatchBytes > maxBatch {
		return fmt.Errorf("%w: CarrierBatchBytes %d is out of [%d, %d]",
			ErrLimits, l.CarrierBatchBytes, minCarrierBatchBytes, maxBatch)
	}

	if l.MaxFramePayload <= 0 || l.MaxFramePayload > maxFramePayloadLimit {
		return fmt.Errorf("%w: MaxFramePayload %d is out of (0, %d]",
			ErrLimits, l.MaxFramePayload, maxFramePayloadLimit)
	}

	if minimum := l.minPendingGlobal(); l.MaxPendingGlobal < minimum {
		return fmt.Errorf("%w: MaxPendingGlobal %d is below the minimum %d "+
			"(control reserves of MaxSessions, one uplink reserve and 1 MiB of downlink)",
			ErrLimits, l.MaxPendingGlobal, minimum)
	}

	if minimum := l.minPendingItemsGlobal(); int64(l.MaxPendingItemsGlobal) < minimum {
		return fmt.Errorf("%w: MaxPendingItemsGlobal %d is below the minimum %d "+
			"(control item reserves of MaxSessions, one uplink item reserve and 1 downlink item)",
			ErrLimits, l.MaxPendingItemsGlobal, minimum)
	}

	return l.validateSessionBudget()
}

// minPendingGlobal is the smallest MaxPendingGlobal that, beside the control
// reserves the manager keeps for all MaxSessions up front (even on an idle
// server), still admits one maximal uplink body and 1 MiB of downlink.
// With the count caps above (MaxSessions <= 1<<30, controlReserveBytes
// below 1<<30) the product stays far below MaxInt64.
func (l Limits) minPendingGlobal() int64 {
	return int64(l.MaxSessions)*l.controlReserveBytes() + l.uplinkReserveBytes() + minDownlinkBytes
}

// minPendingItemsGlobal is minPendingGlobal for items: the control item
// reserves of MaxSessions, one uplink item reserve and 1 downlink item. It
// is computed in int64 so that it cannot overflow on 32-bit builds.
func (l Limits) minPendingItemsGlobal() int64 {
	return int64(l.MaxSessions)*int64(l.controlReserveItems()) + int64(l.uplinkReserveItems()) + 1
}

// minPendingPerSession is the smallest MaxPendingPerSession that leaves the
// downlink some room beside the control and uplink reserves. With less, no
// downlink data can ever be queued and every session stalls.
func (l Limits) minPendingPerSession() int64 {
	return l.controlReserveBytes() + l.uplinkReserveBytes() + minDownlinkBytes
}

// minPendingItemsPerSession is the smallest MaxPendingItemsPerSession that
// leaves the downlink at least one item beside the control and uplink
// reserves. With less, no downlink DATA can ever be queued.
func (l Limits) minPendingItemsPerSession() int {
	return l.controlReserveItems() + l.uplinkReserveItems() + 1
}

// validateSessionBudget checks the per-session byte and item budgets. It
// must hold for the global limits and for every profile's merged limits.
func (l Limits) validateSessionBudget() error {
	if minimum := l.minPendingPerSession(); l.MaxPendingPerSession < minimum {
		return fmt.Errorf("%w: MaxPendingPerSession %d is below the minimum %d "+
			"(control and uplink reserves plus 1 MiB of downlink)",
			ErrLimits, l.MaxPendingPerSession, minimum)
	}

	if minimum := l.minPendingItemsPerSession(); l.MaxPendingItemsPerSession < minimum {
		return fmt.Errorf("%w: MaxPendingItemsPerSession %d is below the minimum %d "+
			"(control and uplink item reserves plus 1 downlink item)",
			ErrLimits, l.MaxPendingItemsPerSession, minimum)
	}

	return nil
}

// merge applies profile overrides. Profile values may only lower global
// limits; zero and higher values are ignored.
func (l Limits) merge(p ProfileLimits) Limits {
	lower := func(dst *int, v int) {
		if v > 0 && v < *dst {
			*dst = v
		}
	}

	lower(&l.MaxSessions, p.MaxSessions)
	lower(&l.MaxStreams, p.MaxStreams)
	lower(&l.MaxStreamsPerSession, p.MaxStreamsPerSession)
	lower(&l.NewSessionsPerMinute, p.NewSessionsPerMinute)
	lower(&l.NewSessionsBurst, p.NewSessionsBurst)
	lower(&l.NewStreamsPerMinute, p.NewStreamsPerMinute)
	lower(&l.NewStreamsBurst, p.NewStreamsBurst)

	if p.MaxPendingPerSession > 0 && p.MaxPendingPerSession < l.MaxPendingPerSession {
		l.MaxPendingPerSession = p.MaxPendingPerSession
	}

	return l
}

// rateBucket is a token bucket. It is NOT safe for concurrent use: the
// owner (the manager) must guard it with its own mutex.
type rateBucket struct {
	perMinute float64
	burst     float64
	tokens    float64
	last      time.Time
}

func newRateBucket(perMinute, burst int, now time.Time) *rateBucket {
	return &rateBucket{
		perMinute: float64(perMinute),
		burst:     float64(burst),
		tokens:    float64(burst),
		last:      now,
	}
}

func (b *rateBucket) take(now time.Time) bool {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+b.perMinute*elapsed.Minutes())
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}

	b.tokens--

	return true
}

// withDefaults returns t with zero fields replaced by the defaults.
func (t Timeouts) withDefaults() Timeouts {
	defaults := DefaultTimeouts()

	for _, f := range []struct {
		value *time.Duration
		def   time.Duration
	}{
		{&t.LongPoll, defaults.LongPoll},
		{&t.ReconnectGrace, defaults.ReconnectGrace},
		{&t.BootstrapLifetime, defaults.BootstrapLifetime},
		{&t.Shutdown, defaults.Shutdown},
	} {
		if *f.value == 0 {
			*f.value = f.def
		}
	}

	return t
}

// ValidateTimeouts checks that t is consistent. A zero field means "use the
// default" and is checked as the default value.
func ValidateTimeouts(t Timeouts) error {
	for _, f := range []struct {
		name  string
		value time.Duration
	}{
		{"LongPoll", t.LongPoll},
		{"ReconnectGrace", t.ReconnectGrace},
		{"BootstrapLifetime", t.BootstrapLifetime},
		{"Shutdown", t.Shutdown},
	} {
		if f.value < 0 {
			return fmt.Errorf("timeout %s is negative", f.name)
		}
	}

	t = t.withDefaults()

	if t.LongPoll < time.Second {
		return errors.New("timeout LongPoll is below 1s")
	}

	// Otherwise the janitor may expire a session while its poll is parked.
	if t.LongPoll >= t.ReconnectGrace {
		return errors.New("timeout LongPoll must be below ReconnectGrace")
	}

	return nil
}

// ValidateLimits checks that l is consistent.
func ValidateLimits(l Limits) error {
	return l.validate()
}
