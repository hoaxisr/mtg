package web

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

type managerHarness struct {
	m     *manager
	clock *testClock
	serve *fakeServe
}

var (
	testIP1 = net.IPv4(10, 0, 0, 1)
	testIP2 = net.IPv4(10, 0, 0, 2)
)

func helloBody() []byte {
	return EncodeFrame(FrameHello, 0, []byte{1})
}

func newTestManager(t *testing.T, profiles []Profile, mutate func(*Limits)) *managerHarness {
	t.Helper()

	limits := DefaultLimits()
	if mutate != nil {
		mutate(&limits)
	}

	if profiles == nil {
		profiles = []Profile{{Index: testProfileIndex}}
	}

	signer, err := newTokenSigner(bytes.Repeat([]byte{7}, tokenKeySize))
	require.NoError(t, err)

	h := &managerHarness{
		clock: &testClock{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)},
		serve: &fakeServe{},
	}

	h.m, err = newManager(profiles, limits, DefaultTimeouts(), signer, h.serve.serve,
		logger.NewNoopLogger(), h.clock.Now)
	require.NoError(t, err)

	t.Cleanup(h.m.closeAll)

	return h
}

func (h *managerHarness) create(t *testing.T, profileIdx int, ip net.IP) (string, *session) {
	t.Helper()

	boot, err := h.m.issueBootstrap(profileIdx, ip)
	require.NoError(t, err)

	tok, s, err := h.m.createSession(boot, helloBody(), ip)
	require.NoError(t, err)

	return tok, s
}

func TestManagerBootstrapLifecycle(t *testing.T) {
	h := newTestManager(t, nil, nil)

	boot, err := h.m.issueBootstrap(testProfileIndex, testIP1)
	require.NoError(t, err)
	assert.Len(t, boot, 43)
	assert.Equal(t, 1, h.m.stats().BootstrapsLive)

	tok, s, err := h.m.createSession(boot, helloBody(), testIP1)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Len(t, tok, 43)
	assert.Equal(t, 0, h.m.stats().BootstrapsLive)
	assert.Equal(t, 1, h.m.stats().SessionsLive)

	found, ok := h.m.lookupSession(tok)
	require.True(t, ok)
	assert.Same(t, s, found)

	tok2, s2, err := h.m.createSession(boot, helloBody(), testIP1)
	require.NoError(t, err)
	assert.Equal(t, tok, tok2)
	assert.Same(t, s, s2)
	assert.Equal(t, uint64(1), h.m.stats().SessionsCreated)

	other := append(helloBody(), EncodeFrame(FramePong, 0, nil)...)
	_, _, err = h.m.createSession(boot, other, testIP1)
	require.ErrorIs(t, err, errNotFound)

	unknown, err := h.m.issueBootstrap(testProfileIndex, testIP1)
	require.NoError(t, err)

	last := byte('A')
	if unknown[42] == last {
		last = 'Q'
	}

	_, _, err = h.m.createSession(unknown[:42]+string(last), helloBody(), testIP1)
	require.ErrorIs(t, err, errNotFound)

	_, _, err = h.m.createSession(tok, helloBody(), testIP1) // a session token is not a bootstrap
	require.ErrorIs(t, err, errNotFound)

	_, ok = h.m.lookupSession(boot) // and vice versa
	assert.False(t, ok)

	h.clock.Advance(3 * time.Minute)
	h.m.cleanup(h.clock.Now())

	_, _, err = h.m.createSession(unknown, helloBody(), testIP1)
	require.ErrorIs(t, err, errNotFound)
	assert.Equal(t, 0, h.m.stats().BootstrapsLive)
}

func TestManagerBootstrapExpiresWithoutCleanup(t *testing.T) {
	h := newTestManager(t, nil, nil)

	boot, err := h.m.issueBootstrap(testProfileIndex, testIP1)
	require.NoError(t, err)

	h.clock.Advance(3 * time.Minute)

	_, _, err = h.m.createSession(boot, helloBody(), testIP1)
	require.ErrorIs(t, err, errNotFound)
}

func TestManagerUnknownProfile(t *testing.T) {
	h := newTestManager(t, nil, nil)

	_, err := h.m.issueBootstrap(testProfileIndex+1, testIP1)
	require.Error(t, err)
}

func TestManagerCapacity(t *testing.T) {
	t.Run("MaxSessions", func(t *testing.T) {
		h := newTestManager(t, nil, func(l *Limits) { l.MaxSessions = 1 })

		tok, _ := h.create(t, testProfileIndex, testIP1)

		boot, err := h.m.issueBootstrap(testProfileIndex, testIP1)
		require.NoError(t, err)

		_, _, err = h.m.createSession(boot, helloBody(), testIP1)
		require.ErrorIs(t, err, errCapacity)
		assert.NotZero(t, h.m.stats().LimitHits)

		require.True(t, h.m.deleteSession(tok))

		_, s, err := h.m.createSession(boot, helloBody(), testIP1)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("session rate", func(t *testing.T) {
		h := newTestManager(t, nil, func(l *Limits) {
			l.NewSessionsBurst = 1
			l.NewSessionsPerMinute = 1
		})

		h.create(t, testProfileIndex, testIP1)

		boot, err := h.m.issueBootstrap(testProfileIndex, testIP1)
		require.NoError(t, err)

		h.clock.Advance(30 * time.Second)

		_, _, err = h.m.createSession(boot, helloBody(), testIP1)
		require.ErrorIs(t, err, errCapacity)

		h.clock.Advance(31 * time.Second)

		_, _, err = h.m.createSession(boot, helloBody(), testIP1)
		require.NoError(t, err)
	})

	t.Run("profile MaxSessions", func(t *testing.T) {
		h := newTestManager(t, []Profile{
			{Index: 0, Limits: ProfileLimits{MaxSessions: 1}},
			{Index: 1},
		}, nil)

		h.create(t, 0, testIP1)

		boot, err := h.m.issueBootstrap(0, testIP1)
		require.NoError(t, err)

		_, _, err = h.m.createSession(boot, helloBody(), testIP1)
		require.ErrorIs(t, err, errCapacity)

		h.create(t, 1, testIP1)
		h.create(t, 1, testIP1)
	})

	t.Run("profile session rate", func(t *testing.T) {
		h := newTestManager(t, []Profile{
			{Index: 0, Limits: ProfileLimits{NewSessionsBurst: 1, NewSessionsPerMinute: 1}},
			{Index: 1},
		}, nil)

		h.create(t, 0, testIP1)

		boot, err := h.m.issueBootstrap(0, testIP1)
		require.NoError(t, err)

		_, _, err = h.m.createSession(boot, helloBody(), testIP1)
		require.ErrorIs(t, err, errCapacity)

		h.create(t, 1, testIP1)
	})

	t.Run("MaxBootstraps", func(t *testing.T) {
		h := newTestManager(t, nil, func(l *Limits) { l.MaxBootstraps = 1 })

		_, err := h.m.issueBootstrap(testProfileIndex, testIP1)
		require.NoError(t, err)

		_, err = h.m.issueBootstrap(testProfileIndex, testIP1)
		require.ErrorIs(t, err, errCapacity)
	})

	t.Run("bootstrap rate", func(t *testing.T) {
		h := newTestManager(t, nil, func(l *Limits) {
			l.NewBootstrapsBurst = 1
			l.NewBootstrapsPerMinute = 1
		})

		_, err := h.m.issueBootstrap(testProfileIndex, testIP1)
		require.NoError(t, err)

		_, err = h.m.issueBootstrap(testProfileIndex, testIP1)
		require.ErrorIs(t, err, errCapacity)
	})

	t.Run("MaxBootstrapsPerIP", func(t *testing.T) {
		h := newTestManager(t, nil, func(l *Limits) { l.MaxBootstrapsPerIP = 1 })

		_, err := h.m.issueBootstrap(testProfileIndex, testIP1)
		require.NoError(t, err)

		_, err = h.m.issueBootstrap(testProfileIndex, testIP1)
		require.ErrorIs(t, err, errCapacity)

		_, err = h.m.issueBootstrap(testProfileIndex, testIP2)
		require.NoError(t, err)
	})

	t.Run("MaxSessionsPerIP", func(t *testing.T) {
		h := newTestManager(t, nil, func(l *Limits) { l.MaxSessionsPerIP = 1 })

		h.create(t, testProfileIndex, testIP1)

		boot, err := h.m.issueBootstrap(testProfileIndex, testIP1)
		require.NoError(t, err)

		_, _, err = h.m.createSession(boot, helloBody(), testIP1)
		require.ErrorIs(t, err, errCapacity)

		h.create(t, testProfileIndex, testIP2)
	})
}

func TestManagerDeleteAndRecentlyClosed(t *testing.T) {
	h := newTestManager(t, nil, nil)

	tok, s := h.create(t, testProfileIndex, testIP1)

	require.True(t, h.m.deleteSession(tok))
	assert.True(t, isClosed(s))

	_, ok := h.m.lookupSession(tok)
	assert.False(t, ok)

	require.True(t, h.m.deleteSession(tok))

	st := h.m.stats()
	assert.Equal(t, 0, st.SessionsLive)
	assert.Equal(t, uint64(1), st.SessionsClosed)

	h.clock.Advance(3 * time.Minute)
	h.m.cleanup(h.clock.Now())

	assert.False(t, h.m.deleteSession(tok))
	assert.False(t, h.m.deleteSession("garbage"))
}

func TestManagerReconnectGrace(t *testing.T) {
	h := newTestManager(t, nil, nil)

	idleTok, idle := h.create(t, testProfileIndex, testIP1)

	h.clock.Advance(time.Minute)
	_, fresh := h.create(t, testProfileIndex, testIP1)

	h.clock.Advance(2 * time.Minute)
	setActivity(fresh, h.clock.Now())

	h.m.cleanup(h.clock.Now())

	assert.True(t, isClosed(idle))
	assert.False(t, isClosed(fresh))

	st := h.m.stats()
	assert.Equal(t, uint64(1), st.SessionsClosed)
	assert.Equal(t, 1, st.SessionsLive)

	assert.True(t, h.m.deleteSession(idleTok)) // remembered as recently closed
}

func TestManagerForgetsSelfClosedSession(t *testing.T) {
	h := newTestManager(t, nil, nil)

	tok, s := h.create(t, testProfileIndex, testIP1)

	_, err := uploadOnce(s, 0, nil) // protocol violation closes the session
	require.Error(t, err)

	_, ok := h.m.lookupSession(tok)
	assert.False(t, ok)

	st := h.m.stats()
	assert.Equal(t, 0, st.SessionsLive)
	assert.Equal(t, uint64(1), st.SessionsClosed)
	assert.True(t, h.m.deleteSession(tok))
}

func TestManagerGlobalPendingReserve(t *testing.T) {
	h := newTestManager(t, nil, nil)
	l := DefaultLimits()

	size := l.MaxPendingGlobal - l.controlReserveBytes()*int64(l.MaxSessions) + 1

	assert.False(t, h.m.changePending(pendingDownlink, size, 1))
	assert.False(t, h.m.changePending(pendingUplink, size, 1))
	assert.True(t, h.m.changePending(pendingControl, size, 1))
	assert.NotZero(t, h.m.stats().LimitHits)

	st := h.m.stats()
	assert.Equal(t, size, st.PendingBytes)
	assert.Equal(t, 1, st.PendingItems)

	assert.True(t, h.m.changePending(pendingControl, -size, -1))
	assert.Equal(t, int64(0), h.m.stats().PendingBytes)

	items := l.MaxPendingItemsGlobal - l.controlReserveItems()*l.MaxSessions + 1
	assert.False(t, h.m.changePending(pendingDownlink, 1, items))
	assert.True(t, h.m.changePending(pendingControl, 1, items))
	assert.False(t, h.m.changePending(pendingControl, l.MaxPendingGlobal, 1))
}

func TestManagerStreams(t *testing.T) {
	h := newTestManager(t, []Profile{
		{Index: 0, Limits: ProfileLimits{MaxStreams: 1}},
		{Index: 1},
	}, func(l *Limits) { l.MaxStreams = 2 })

	now := h.clock.Now()

	require.True(t, h.m.acquireStream(0, now))
	assert.False(t, h.m.acquireStream(0, now))
	require.True(t, h.m.acquireStream(1, now))
	assert.False(t, h.m.acquireStream(1, now))

	st := h.m.stats()
	assert.Equal(t, 2, st.StreamsLive)
	assert.Equal(t, uint64(2), st.StreamsOpened)
	assert.Equal(t, uint64(2), st.StreamsRejected)

	h.m.releaseStream(0)
	require.True(t, h.m.acquireStream(0, now))
}

func TestManagerStreamRate(t *testing.T) {
	h := newTestManager(t, nil, func(l *Limits) {
		l.NewStreamsBurst = 1
		l.NewStreamsPerMinute = 1
	})

	now := h.clock.Now()

	require.True(t, h.m.acquireStream(testProfileIndex, now))
	h.m.releaseStream(testProfileIndex)
	assert.False(t, h.m.acquireStream(testProfileIndex, now))
	assert.True(t, h.m.acquireStream(testProfileIndex, now.Add(time.Minute)))
}

func TestManagerSessionUsesManagerBudget(t *testing.T) {
	h := newTestManager(t, nil, nil)

	_, s := h.create(t, testProfileIndex, testIP1)

	require.True(t, s.queueDownlink(Frame{Type: FrameClose, StreamID: 1}, pendingControl))
	assert.Equal(t, int64(queueItemCost), h.m.stats().PendingBytes)

	_, err := uploadOnce(s, 1, openFrame(5))
	require.NoError(t, err)
	assert.Equal(t, 1, h.m.stats().StreamsLive)

	h.m.closeAll()

	st := h.m.stats()
	assert.Equal(t, int64(0), st.PendingBytes)
	assert.Equal(t, 0, st.PendingItems)
	assert.Equal(t, 0, st.StreamsLive)
	assert.Equal(t, 0, st.SessionsLive)
	assert.True(t, isClosed(s))
	s.wait()
}

func TestManagerAddBytes(t *testing.T) {
	h := newTestManager(t, nil, nil)

	h.m.addBytes(10, 20)
	h.m.addBytes(1, 2)

	st := h.m.stats()
	assert.Equal(t, uint64(11), st.BytesUp)
	assert.Equal(t, uint64(22), st.BytesDown)
}

func TestSessionControlQueueOverflow(t *testing.T) {
	h := newTestManager(t, nil, func(l *Limits) { l.MaxStreamsPerSession = 1 })

	_, flooder := h.create(t, testProfileIndex, testIP1)
	_, sibling := h.create(t, testProfileIndex, testIP2)

	require.Equal(t, maxControlItemsPerSession, flooder.controlItemsCap())

	// The sibling has a live stream with a queued CLOSE of a refused OPEN.
	_, err := uploadOnce(sibling, 1, batch(openFrame(1), openFrame(2)))
	require.NoError(t, err)
	waitServed(t, h.serve, 1)

	// OPEN 1 is admitted, the other OPENs are refused and each queues a
	// CLOSE: exactly the cap is still fine.
	frames := [][]byte{openFrame(1)}
	for id := range uint32(maxControlItemsPerSession) {
		frames = append(frames, openFrame(id+2))
	}

	_, err = uploadOnce(flooder, 1, batch(frames...))
	require.NoError(t, err)
	require.False(t, isClosed(flooder))
	assert.Equal(t, maxControlItemsPerSession+1, h.m.stats().PendingItems)

	// One more refused OPEN overflows the flooder's control queue.
	_, err = uploadOnce(flooder, 2, batch(openFrame(5000)))
	require.ErrorIs(t, err, errSessionClosed)
	assert.True(t, isClosed(flooder))

	// Its budget is gone; the sibling keeps its CLOSE and its stream.
	st := h.m.stats()
	assert.Equal(t, 1, st.PendingItems)
	assert.Equal(t, 1, st.StreamsLive)
	assert.False(t, isClosed(sibling))

	// The sibling's downlink still flows: proxy-side data reaches its poll.
	conn := h.serve.conn(t, 0)
	_, err = conn.Write([]byte("still here"))
	require.NoError(t, err)

	var (
		data   []byte
		cursor uint64
	)

	require.Eventually(t, func() bool {
		body, next, err := pollOnce(context.Background(), sibling, cursor, 50*time.Millisecond)
		require.NoError(t, err)

		cursor = next
		if len(body) == 0 {
			return false
		}

		parsed, err := ParseFrames(body, MaxFramePayload)
		require.NoError(t, err)

		for _, f := range parsed {
			if f.Type == FrameData && f.StreamID == 1 {
				data = append(data, f.Payload...)
			}
		}

		return len(data) > 0
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, "still here", string(data))
}
