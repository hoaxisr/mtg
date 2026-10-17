package web

import (
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLimitsValidate(t *testing.T) {
	require.NoError(t, DefaultLimits().validate())
}

func TestDefaultTimeouts(t *testing.T) {
	to := DefaultTimeouts()
	assert.Equal(t, 25*time.Second, to.LongPoll)
	assert.Equal(t, 2*time.Minute, to.ReconnectGrace)
	assert.Equal(t, 2*time.Minute, to.BootstrapLifetime)
	assert.Equal(t, 15*time.Second, to.Shutdown)
}

func TestLimitsValidateRejects(t *testing.T) {
	tests := map[string]func(*Limits){
		"batch too small":   func(l *Limits) { l.CarrierBatchBytes = 100 << 10 },
		"batch above body":  func(l *Limits) { l.MaxBodyBytes = 512 << 10; l.CarrierBatchBytes = 1 << 20 },
		"batch above 2MiB":  func(l *Limits) { l.MaxBodyBytes = 4 << 20; l.CarrierBatchBytes = 3 << 20 },
		"reserve bytes":     func(l *Limits) { l.MaxSessions = 100000 },
		"reserve items":     func(l *Limits) { l.MaxPendingItemsGlobal = 1000 },
		"reviewer global":   func(l *Limits) { l.MaxPendingGlobal = 13721601 },
		"14MiB global":      func(l *Limits) { l.MaxPendingGlobal = 14 << 20 },
		"frame payload big": func(l *Limits) { l.MaxFramePayload = 2 << 20 },
		"frame payload 0":   func(l *Limits) { l.MaxFramePayload = 0 },
		"sessions MaxInt":   func(l *Limits) { l.MaxSessions = math.MaxInt },
		"streams/session":   func(l *Limits) { l.MaxStreamsPerSession = math.MaxInt / 2 },
		"huge pending":      func(l *Limits) { l.MaxPendingGlobal = math.MaxInt64 },
		"huge per ip":       func(l *Limits) { l.MaxSessionsPerIP = math.MaxInt },
		"zero streams":      func(l *Limits) { l.MaxStreams = 0 },
		"negative per ip":   func(l *Limits) { l.MaxSessionsPerIP = -1 },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			l := DefaultLimits()
			mutate(&l)
			err := l.validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrLimits)
		})
	}
}

func TestLimitsAllowZeroPerIP(t *testing.T) {
	l := DefaultLimits()
	l.MaxSessionsPerIP, l.MaxBootstrapsPerIP = 0, 0
	assert.NoError(t, l.validate())
}

func TestReserves(t *testing.T) {
	l := DefaultLimits()
	assert.Equal(t, 16+3*128, l.controlReserveItems())
	assert.Equal(t, int64(16+3*128)*(queueItemCost+FrameHeaderSize+4), l.controlReserveBytes())
	assert.Equal(t, int64(2<<20+4096*queueItemCost), l.uplinkReserveBytes())
}

func TestMergeOnlyLowers(t *testing.T) {
	g := DefaultLimits()

	m := g.merge(ProfileLimits{MaxStreams: 10, MaxPendingPerSession: 8 << 20})
	assert.Equal(t, 10, m.MaxStreams)
	assert.Equal(t, int64(8<<20), m.MaxPendingPerSession)
	assert.Equal(t, g.MaxSessions, m.MaxSessions)
	assert.NoError(t, m.validateSessionBudget())

	// merge itself does not judge: a too low override is caught by
	// validateSessionBudget, which newManager runs on every profile.
	m = g.merge(ProfileLimits{MaxPendingPerSession: 1024})
	assert.Equal(t, int64(1024), m.MaxPendingPerSession)
	assert.ErrorIs(t, m.validateSessionBudget(), ErrLimits)

	m = g.merge(ProfileLimits{MaxStreams: 99999, MaxPendingPerSession: 1 << 40})
	assert.Equal(t, g.MaxStreams, m.MaxStreams)
	assert.Equal(t, g.MaxPendingPerSession, m.MaxPendingPerSession)

	assert.Equal(t, g, g.merge(ProfileLimits{}))
}

func TestLimitsPendingPerSessionMinimum(t *testing.T) {
	l := DefaultLimits()
	minimum := l.controlReserveBytes() + l.uplinkReserveBytes() + (1 << 20)
	assert.Equal(t, minimum, l.minPendingPerSession())

	l.MaxPendingPerSession = minimum - 1
	err := l.validate()
	require.ErrorIs(t, err, ErrLimits)
	assert.Contains(t, err.Error(), strconv.FormatInt(minimum, 10))

	l.MaxPendingPerSession = minimum
	assert.NoError(t, l.validate())
}

func TestLimitsPendingItemsPerSessionMinimum(t *testing.T) {
	l := DefaultLimits()
	assert.Equal(t, 4096, l.uplinkReserveItems())

	minimum := l.controlReserveItems() + l.uplinkReserveItems() + 1
	assert.Equal(t, minimum, l.minPendingItemsPerSession())

	// 4096 - 400 - 4096 leaves no downlink item at all.
	l.MaxPendingItemsPerSession = 4096
	err := l.validate()
	require.ErrorIs(t, err, ErrLimits)
	assert.Contains(t, err.Error(), "MaxPendingItemsPerSession")
	assert.Contains(t, err.Error(), strconv.Itoa(minimum))

	l.MaxPendingItemsPerSession = minimum - 1
	require.ErrorIs(t, l.validate(), ErrLimits)

	l.MaxPendingItemsPerSession = minimum
	require.NoError(t, l.validate())

	s := &session{limits: l}
	assert.Equal(t, l.uplinkReserveItems(), s.uplinkReserveItems())
	assert.Equal(t, 1, s.downlinkItemsCap())

	// A small body shrinks the uplink item reserve with it.
	l.MaxBodyBytes = 8000
	assert.Equal(t, 1000, l.uplinkReserveItems())
}

func TestNewManagerRejectsLowProfilePending(t *testing.T) {
	g := DefaultLimits()
	low := Profile{Index: 3, Secret: handlerSecret(7)}

	// Lowering MaxStreamsPerSession lowers the control reserve, and with
	// it the minimum.
	low.Limits = ProfileLimits{MaxStreamsPerSession: 10}
	minimum := g.merge(low.Limits).minPendingPerSession()

	signer := newTestSigner(t, "limits")
	build := func(pending int64) error {
		p := low
		p.Limits.MaxPendingPerSession = pending
		_, err := newManager([]Profile{p}, g, DefaultTimeouts(), signer,
			(&fakeServe{}).serve, logger.NewNoopLogger(), time.Now)

		return err
	}

	err := build(minimum - 1)
	require.ErrorIs(t, err, ErrLimits)
	assert.Contains(t, err.Error(), "profile 3")

	require.NoError(t, build(minimum))

	_, err = NewHandler(Options{
		Hostname: testHostname,
		Profiles: []Profile{{Index: 0, Secret: low.Secret, Limits: ProfileLimits{MaxPendingPerSession: 1024}}},
		Serve:    (&fakeServe{}).serve,
		Public:   &recordingPublic{},
	})
	require.ErrorIs(t, err, ErrOptions)
	assert.ErrorIs(t, err, ErrLimits)
}

func TestTimeoutsLongPollBelowReconnectGrace(t *testing.T) {
	to := Timeouts{LongPoll: time.Minute, ReconnectGrace: time.Minute}
	require.ErrorIs(t, applyTimeoutDefaults(&to), ErrOptions)

	to = Timeouts{LongPoll: 3 * time.Minute} // default grace is 2m
	require.ErrorIs(t, applyTimeoutDefaults(&to), ErrOptions)

	to = Timeouts{LongPoll: time.Minute - time.Millisecond, ReconnectGrace: time.Minute}
	require.NoError(t, applyTimeoutDefaults(&to))

	to = Timeouts{}
	require.NoError(t, applyTimeoutDefaults(&to))
	assert.Equal(t, DefaultTimeouts(), to)
}

func TestValidateTimeouts(t *testing.T) {
	require.NoError(t, ValidateTimeouts(Timeouts{}))
	require.NoError(t, ValidateTimeouts(DefaultTimeouts()))
	require.NoError(t, ValidateTimeouts(Timeouts{LongPoll: time.Second}))

	for name, to := range map[string]Timeouts{
		"negative":           {Shutdown: -time.Second},
		"long poll below 1s": {LongPoll: 500 * time.Millisecond},
		"long poll >= grace": {LongPoll: 3 * time.Minute},
		"grace below poll":   {ReconnectGrace: 10 * time.Second},
	} {
		assert.Error(t, ValidateTimeouts(to), name)
	}
}

func TestRateBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newRateBucket(60, 2, now)

	assert.True(t, b.take(now))
	assert.True(t, b.take(now))
	assert.False(t, b.take(now))

	now = now.Add(time.Second)
	assert.True(t, b.take(now))
	assert.False(t, b.take(now))

	now = now.Add(time.Minute)
	assert.True(t, b.take(now))
	assert.True(t, b.take(now))
	assert.False(t, b.take(now))
}

func TestLimitsPendingGlobalMinimum(t *testing.T) {
	l := DefaultLimits()

	// the manager keeps the control reserve of every possible session
	idle := int64(l.MaxSessions) * l.controlReserveBytes()
	assert.Equal(t, int64(13721600), idle)

	minimum := idle + l.uplinkReserveBytes() + (1 << 20)
	assert.Equal(t, minimum, l.minPendingGlobal())

	l.MaxPendingGlobal = 13721601 // one byte above the idle reserves
	err := l.validate()
	require.ErrorIs(t, err, ErrLimits)
	assert.Contains(t, err.Error(), "MaxPendingGlobal")
	assert.Contains(t, err.Error(), strconv.FormatInt(minimum, 10))

	l.MaxPendingGlobal = minimum - 1
	require.ErrorIs(t, l.validate(), ErrLimits)

	l.MaxPendingGlobal = minimum
	require.NoError(t, l.validate())

	// what is left beside the idle reserves takes one maximal upload and
	// still leaves the downlink 1 MiB
	assert.Equal(t, l.uplinkReserveBytes()+(1<<20), l.MaxPendingGlobal-idle)
}

func TestLimitsPendingItemsGlobalMinimum(t *testing.T) {
	l := DefaultLimits()

	minimum := int64(l.MaxSessions*l.controlReserveItems() + l.uplinkReserveItems() + 1)
	assert.Equal(t, minimum, l.minPendingItemsGlobal())

	l.MaxPendingItemsGlobal = l.MaxSessions*l.controlReserveItems() + 1
	err := l.validate()
	require.ErrorIs(t, err, ErrLimits)
	assert.Contains(t, err.Error(), "MaxPendingItemsGlobal")
	assert.Contains(t, err.Error(), strconv.FormatInt(minimum, 10))

	l.MaxPendingItemsGlobal = int(minimum) - 1
	require.ErrorIs(t, l.validate(), ErrLimits)

	l.MaxPendingItemsGlobal = int(minimum)
	require.NoError(t, l.validate())
}

func TestLimitsPendingGlobalMinimumNoOverflow(t *testing.T) {
	l := DefaultLimits()
	l.MaxSessions = maxCount
	l.MaxStreamsPerSession = maxStreamsPerSessionLimit
	l.MaxPendingGlobal = maxBytesLimit
	l.MaxPendingItemsGlobal = maxCount

	assert.Positive(t, l.minPendingGlobal())
	assert.Positive(t, l.minPendingItemsGlobal())
	require.ErrorIs(t, l.validate(), ErrLimits)
}
