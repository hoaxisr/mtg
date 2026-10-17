package web

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib"
)

// downlinkRetryInterval is how often a downlink pump retries queueing data
// that the global budget refused. Session-local releases wake pumps
// immediately; releases in other sessions are only noticed by this timer.
const downlinkRetryInterval = 50 * time.Millisecond

// maxControlItemsPerSession caps the control frames (WINDOW, CLOSE) a single
// session may hold queued or unacknowledged. The control reserve is a pool
// shared by all sessions; without this cap one session could fill it, for
// example with a flood of refused OPENs that a client never polls the CLOSEs
// for, and starve every other session's control frames. A session hitting
// the cap is closed as a protocol violation. Configurations with more
// streams per session get their whole control reserve
// (Limits.controlReserveItems) instead.
const maxControlItemsPerSession = 1024

// serveFunc hands a proxy-facing stream end to mtglib. It must not block
// for the lifetime of the stream.
type serveFunc func(conn essentials.Conn, secretIdx int) error

// pendingClass is an accounting class of queued items.
type pendingClass int

const (
	pendingControl pendingClass = iota
	pendingUplink
	pendingDownlink

	pendingClasses = 3
)

// budgetSink is a global budget (implemented by the manager). Sessions call
// it while holding their own mutex: an implementation must never call back
// into a session while holding its own lock.
type budgetSink interface {
	// changePending applies a delta; false means refused and nothing changed.
	// Negative deltas (releases) are never refused.
	changePending(class pendingClass, bytes int64, items int) bool
	acquireStream(profileIdx int, now time.Time) bool
	releaseStream(profileIdx int)
}

var (
	errSessionProtocol = errors.New("web session protocol violation")
	errBackpressure    = errors.New("web session backpressure")
	errConcurrent      = errors.New("concurrent web request")
	errSessionClosed   = errors.New("web session is closed")
	errCursor          = fmt.Errorf("%w: unexpected downlink cursor", errSessionProtocol)
)

// downItem is a queued downlink frame. Its payload is owned by the queue.
type downItem struct {
	frame Frame
	class pendingClass
	// bytes and items are what this item holds against the budgets.
	bytes int64
	items int
	// sent is set once the item left the pending queue (taken into a
	// batch); a sent item is never coalesced into.
	sent bool
}

type stream struct {
	id          uint32
	proxySide   essentials.Conn
	sessionSide net.Conn
	acquired    bool
	closed      bool
	done        chan struct{}

	// upQueue are client DATA payloads not yet written to sessionSide.
	upQueue [][]byte
	upWake  chan struct{}

	downWake chan struct{}

	// receiveWindow is how many bytes the client may still send to us.
	receiveWindow int64
	// sendCredit is how many bytes we may still send to the client.
	sendCredit int64

	// pendingWindow is this stream's WINDOW item still in the pending
	// queue, if any; further grants are summed into it.
	pendingWindow *downItem
}

// session is a single WEB proxy session. One mutex guards all session and
// stream state; per-stream pumps are goroutines that never hold it while
// doing I/O.
type session struct {
	mu sync.Mutex

	profile  *Profile
	limits   Limits
	sink     budgetSink
	serve    serveFunc
	clientIP net.IP
	logger   mtglib.Logger
	now      func() time.Time

	streams    map[uint32]*stream
	tombstones map[uint32]struct{}
	tombRing   []uint32
	tombNext   int

	pendingBytes [pendingClasses]int64
	pendingItems [pendingClasses]int

	// downlink is the ordered queue of frames not yet taken into a batch.
	downlink []*downItem
	// downlinkNotify is signalled whenever something is queued.
	downlinkNotify chan struct{}

	lastSeq    uint64
	lastDigest [sha256.Size]byte
	upBusy     bool

	// downCursor is the cursor of the last batch handed out (0: none yet).
	downCursor uint64
	// unacked is the last batch handed out and not yet acknowledged (its
	// cursor is downCursor); its items keep their budget until the ack.
	// unackedBody is its encoded form, replayed verbatim on a retry.
	unacked     []*downItem
	unackedBody []byte
	// waiter is closed to supersede the currently parked poll.
	waiter chan struct{}
	// downBusy is the downlink write slot: set while a handler writes a
	// downlink body handed out by poll, until endDownload.
	downBusy bool

	isClosed bool
	done     chan struct{}
	activity time.Time

	wg sync.WaitGroup
}

// newSession creates a session. limits are the profile's merged limits.
func newSession(profile *Profile, limits Limits, sink budgetSink, serve serveFunc,
	clientIP net.IP, logger mtglib.Logger, now func() time.Time,
) *session {
	return &session{
		profile:        profile,
		limits:         limits,
		sink:           sink,
		serve:          serve,
		clientIP:       append(net.IP(nil), clientIP...),
		logger:         logger.Named("web-session").BindInt("profile", profile.Index),
		now:            now,
		streams:        map[uint32]*stream{},
		tombstones:     map[uint32]struct{}{},
		tombRing:       make([]uint32, 0, min(limits.MaxClosedStreamIDs, 64)),
		downlinkNotify: make(chan struct{}, 1),
		done:           make(chan struct{}),
		activity:       now(),
	}
}

func (s *session) closed() <-chan struct{} {
	return s.done
}

func (s *session) lastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.activity
}

// wait blocks until every pump goroutine has exited. Call after close.
func (s *session) wait() {
	s.wg.Wait()
}

// close is idempotent: it closes every stream pair, releases every budget
// the session holds and stops the pumps.
func (s *session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeLocked()
}

func (s *session) closeLocked() {
	if s.isClosed {
		return
	}

	s.isClosed = true

	for _, st := range s.streams {
		s.closeStreamLocked(st, false, false) // the whole queue is dropped below
	}

	for class := range pendingClasses {
		if s.pendingBytes[class] != 0 || s.pendingItems[class] != 0 {
			s.sink.changePending(pendingClass(class), -s.pendingBytes[class], -s.pendingItems[class])
		}

		s.pendingBytes[class] = 0
		s.pendingItems[class] = 0
	}

	for _, it := range s.downlink {
		it.sent = true
	}

	s.downlink = nil
	s.unacked = nil
	s.unackedBody = nil

	close(s.done)
	s.logger.Debug("session closed")
}

// --- budgets ---------------------------------------------------------------

func (s *session) uplinkReserveItems() int {
	return s.limits.uplinkReserveItems()
}

func (s *session) totalPendingLocked() (int64, int) {
	var (
		bytes int64
		items int
	)

	for class := range pendingClasses {
		bytes += s.pendingBytes[class]
		items += s.pendingItems[class]
	}

	return bytes, items
}

// sessionAllowsLocked checks per-session partitions. Control may use the
// whole session budget; data classes leave the control reserve intact, and
// downlink additionally leaves the uplink reserve.
func (s *session) sessionAllowsLocked(class pendingClass, bytes int64, items int) bool {
	totalBytes, totalItems := s.totalPendingLocked()
	if totalBytes+bytes > s.limits.MaxPendingPerSession ||
		totalItems+items > s.limits.MaxPendingItemsPerSession {
		return false
	}

	dataBytes := s.pendingBytes[pendingUplink] + s.pendingBytes[pendingDownlink]
	dataItems := s.pendingItems[pendingUplink] + s.pendingItems[pendingDownlink]

	switch class {
	case pendingControl:
		return true
	case pendingUplink:
		return dataBytes+bytes <= s.limits.MaxPendingPerSession-s.limits.controlReserveBytes() &&
			dataItems+items <= s.limits.MaxPendingItemsPerSession-s.limits.controlReserveItems()
	case pendingDownlink:
		return dataBytes+bytes <= s.limits.MaxPendingPerSession-s.limits.controlReserveBytes() &&
			dataItems+items <= s.limits.MaxPendingItemsPerSession-s.limits.controlReserveItems() &&
			s.pendingBytes[pendingDownlink]+bytes <= s.downlinkBytesCap() &&
			s.pendingItems[pendingDownlink]+items <= s.downlinkItemsCap()
	}

	return false
}

// controlItemsCap is how many control items the session may hold.
func (s *session) controlItemsCap() int {
	return max(maxControlItemsPerSession, s.limits.controlReserveItems())
}

func (s *session) downlinkBytesCap() int64 {
	return s.limits.MaxPendingPerSession - s.limits.controlReserveBytes() - s.limits.uplinkReserveBytes()
}

func (s *session) downlinkItemsCap() int {
	return s.limits.MaxPendingItemsPerSession - s.limits.controlReserveItems() - s.uplinkReserveItems()
}

// downlinkHeadroomLocked is how many payload bytes a new downlink DATA item
// may carry right now.
func (s *session) downlinkHeadroomLocked() int64 {
	if s.pendingItems[pendingDownlink] >= s.downlinkItemsCap() {
		return 0
	}

	return max(0, s.downlinkBytesCap()-s.pendingBytes[pendingDownlink]-queueItemCost-FrameHeaderSize)
}

func (s *session) chargeLocked(class pendingClass, bytes int64, items int) bool {
	if !s.sessionAllowsLocked(class, bytes, items) {
		return false
	}

	if !s.sink.changePending(class, bytes, items) {
		return false
	}

	s.pendingBytes[class] += bytes
	s.pendingItems[class] += items

	return true
}

func (s *session) releaseLocked(class pendingClass, bytes int64, items int) {
	if s.isClosed || (bytes == 0 && items == 0) {
		return // everything was released in bulk by closeLocked
	}

	s.pendingBytes[class] -= bytes
	s.pendingItems[class] -= items
	s.sink.changePending(class, -bytes, -items)
}

// popDownlinkLocked removes the first n pending items. The caller keeps
// them (and their budget) until they are acknowledged.
func (s *session) popDownlinkLocked(n int) []*downItem {
	n = min(n, len(s.downlink))
	items := make([]*downItem, n)
	copy(items, s.downlink[:n])

	for i := range n {
		s.downlink[i] = nil
		items[i].sent = true

		if st := s.streams[items[i].frame.StreamID]; st != nil && st.pendingWindow == items[i] {
			st.pendingWindow = nil
		}
	}

	s.downlink = s.downlink[n:]

	return items
}

// --- downlink queue --------------------------------------------------------

// queueDownlink queues a frame for the client. For control frames a refusal
// closes the session.
func (s *session) queueDownlink(f Frame, class pendingClass) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.queueDownlinkLocked(f, class)
}

func (s *session) queueDownlinkLocked(f Frame, class pendingClass) bool {
	if s.isClosed {
		return false
	}

	if s.coalesceLocked(f) {
		return true
	}

	if class == pendingControl && s.pendingItems[pendingControl] >= s.controlItemsCap() {
		s.logger.Info("protocol violation: control queue overflow")
		s.closeLocked()

		return false
	}

	size := int64(len(f.Payload))
	if !s.chargeLocked(class, size+queueItemCost, 1) {
		if class == pendingControl {
			s.logger.Warning("control frame refused by budget, closing session")
			s.closeLocked()
		}

		return false
	}

	it := &downItem{
		frame: Frame{
			Type:     f.Type,
			StreamID: f.StreamID,
			Payload:  append([]byte(nil), f.Payload...),
		},
		class: class,
		bytes: size + queueItemCost,
		items: 1,
	}
	s.downlink = append(s.downlink, it)

	if f.Type == FrameWindow {
		if st := s.streams[f.StreamID]; st != nil {
			st.pendingWindow = it
		}
	}

	wake(s.downlinkNotify)

	return true
}

// coalesceLocked merges f into an existing pending item: WINDOW into the
// stream's pending WINDOW (sum), DATA into the last queued item if it is
// DATA of the same stream (up to limits.MaxFramePayload).
func (s *session) coalesceLocked(f Frame) bool {
	switch f.Type { //nolint: exhaustive
	case FrameWindow:
		st := s.streams[f.StreamID]
		if st == nil || st.pendingWindow == nil || st.pendingWindow.sent {
			return false
		}

		add, err := WindowAmount(f.Payload)
		if err != nil {
			return false
		}

		cur, _ := WindowAmount(st.pendingWindow.frame.Payload)
		sum := min(uint64(cur)+uint64(add), math.MaxUint32)
		st.pendingWindow.frame.Payload = WindowPayload(uint32(sum)) //nolint: gosec

		return true
	case FrameData:
		if len(s.downlink) == 0 {
			return false
		}

		last := s.downlink[len(s.downlink)-1]
		if last.sent || last.frame.Type != FrameData || last.frame.StreamID != f.StreamID ||
			len(last.frame.Payload)+len(f.Payload) > s.limits.MaxFramePayload {
			return false
		}

		if !s.chargeLocked(last.class, int64(len(f.Payload)), 0) {
			return false
		}

		last.frame.Payload = append(last.frame.Payload, f.Payload...)
		last.bytes += int64(len(f.Payload))
		wake(s.downlinkNotify)

		return true
	}

	return false
}

// --- streams ---------------------------------------------------------------

func (s *session) addTombstoneLocked(id uint32) {
	if _, ok := s.tombstones[id]; ok {
		return
	}

	if len(s.tombRing) < s.limits.MaxClosedStreamIDs {
		s.tombRing = append(s.tombRing, id)
	} else {
		delete(s.tombstones, s.tombRing[s.tombNext])
		s.tombRing[s.tombNext] = id
		s.tombNext = (s.tombNext + 1) % len(s.tombRing)
	}

	s.tombstones[id] = struct{}{}
}

// closeStreamLocked closes a stream pair, tombstones its id, releases its
// budget and stream slot and, if sendClose, queues CLOSE to the client.
// dropDownlink (a client CLOSE: an abort) also drops the stream's unsent
// DATA and WINDOW items; on a proxy-side close they are kept, as those
// bytes precede the CLOSE.
func (s *session) closeStreamLocked(st *stream, sendClose, dropDownlink bool) {
	if st.closed {
		return
	}

	st.closed = true
	close(st.done)

	// Closing our end only: the proxy side then reads a clean io.EOF and
	// its writes fail; the relay closes the proxy side itself.
	_ = st.sessionSide.Close()

	delete(s.streams, st.id)
	s.addTombstoneLocked(st.id)

	var queued int64
	for _, chunk := range st.upQueue {
		queued += int64(len(chunk)) + queueItemCost
	}

	s.releaseLocked(pendingUplink, queued, len(st.upQueue))
	st.upQueue = nil

	if dropDownlink {
		s.dropStreamDownlinkLocked(st)
	}

	if st.acquired {
		st.acquired = false
		s.sink.releaseStream(s.profile.Index)
	}

	s.logger.BindInt("stream", int(st.id)).Debug("stream closed")

	if sendClose {
		s.queueDownlinkLocked(Frame{Type: FrameClose, StreamID: st.id}, pendingControl)
	}
}

// dropStreamDownlinkLocked removes the stream's unsent DATA and WINDOW
// items from the pending queue and releases their budget.
func (s *session) dropStreamDownlinkLocked(st *stream) {
	kept := s.downlink[:0]

	for _, it := range s.downlink {
		if it.frame.StreamID == st.id && (it.frame.Type == FrameData || it.frame.Type == FrameWindow) {
			it.sent = true
			s.releaseLocked(it.class, it.bytes, it.items)

			continue
		}

		kept = append(kept, it)
	}

	clear(s.downlink[len(kept):])
	s.downlink = kept
	st.pendingWindow = nil
}

// openStreamLocked admits a new stream. It returns nil if the stream was
// refused (the id is tombstoned and CLOSE is queued).
func (s *session) openStreamLocked(id uint32) *stream {
	if len(s.streams) >= s.limits.MaxStreamsPerSession ||
		!s.sink.acquireStream(s.profile.Index, s.now()) {
		s.logger.BindInt("stream", int(id)).Debug("stream refused by limits")
		s.addTombstoneLocked(id)
		s.queueDownlinkLocked(Frame{Type: FrameClose, StreamID: id}, pendingControl)

		return nil
	}

	proxySide, sessionSide := newStreamPair(s.clientIP)
	st := &stream{
		id:            id,
		proxySide:     proxySide,
		sessionSide:   sessionSide,
		acquired:      true,
		done:          make(chan struct{}),
		upWake:        make(chan struct{}, 1),
		downWake:      make(chan struct{}, 1),
		receiveWindow: InitialStreamWindow,
		sendCredit:    InitialStreamWindow,
	}
	s.streams[id] = st

	return st
}

// startStream hands the proxy side to serve (without the session lock) and
// starts the pumps on success.
func (s *session) startStream(st *stream) {
	log := s.logger.BindInt("stream", int(st.id))

	s.mu.Lock()
	alreadyClosed := st.closed
	s.mu.Unlock()

	if alreadyClosed {
		return
	}

	if err := s.serve(st.proxySide, s.profile.Index); err != nil {
		log.DebugError("cannot serve stream", err)

		_ = st.proxySide.Close()

		s.mu.Lock()
		s.closeStreamLocked(st, true, false)
		s.mu.Unlock()

		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if st.closed || s.isClosed {
		return
	}

	log.Debug("stream opened")
	s.wg.Add(2) //nolint: mnd

	go s.uplinkPump(st)
	go s.downlinkPump(st)
}

func (s *session) uplinkPump(st *stream) {
	defer s.wg.Done()

	for {
		s.mu.Lock()

		for len(st.upQueue) == 0 {
			if st.closed || s.isClosed {
				s.mu.Unlock()

				return
			}

			s.mu.Unlock()

			select {
			case <-st.upWake:
			case <-st.done:
			}

			s.mu.Lock()
		}

		chunk := st.upQueue[0]
		st.upQueue[0] = nil
		st.upQueue = st.upQueue[1:]

		s.mu.Unlock()

		n, err := st.sessionSide.Write(chunk)

		s.mu.Lock()
		s.releaseLocked(pendingUplink, int64(len(chunk))+queueItemCost, 1)

		if n > 0 && !st.closed {
			st.receiveWindow += int64(n)
			s.queueDownlinkLocked(Frame{
				Type:     FrameWindow,
				StreamID: st.id,
				Payload:  WindowPayload(uint32(n)), //nolint: gosec
			}, pendingControl)
		}

		if err != nil {
			s.closeStreamLocked(st, true, false)
			s.mu.Unlock()

			return
		}

		s.mu.Unlock()
	}
}

// downlinkBufPool holds DataChunk read buffers for the downlink pumps, so a
// stream holds one only while it has data to read.
var downlinkBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, DataChunk)

		return &b
	},
}

func (s *session) downlinkPump(st *stream) {
	defer s.wg.Done()

	for {
		allowance, ok := s.downlinkAllowance(st)
		if !ok {
			return
		}

		queued, err := s.readDownlink(st, allowance)
		if !queued {
			return
		}

		if err != nil {
			s.mu.Lock()
			s.closeStreamLocked(st, true, false)
			s.mu.Unlock()

			return
		}
	}
}

// readDownlink reads up to allowance bytes from the stream and queues them.
// It first waits for data with a zero-length read (sessionSide is a
// net.Pipe end, whose Read blocks until the peer writes without consuming
// anything when b is empty), so an idle stream holds no read buffer. The
// buffer is pooled; queueDownlinkLocked copies the payload, so the queued
// frame never aliases it. queued is false if the stream or session closed.
func (s *session) readDownlink(st *stream, allowance int) (queued bool, err error) {
	if _, err = st.sessionSide.Read(nil); err != nil {
		return true, err
	}

	bp, _ := downlinkBufPool.Get().(*[]byte)
	defer downlinkBufPool.Put(bp)

	buf := (*bp)[:allowance]

	k, err := st.sessionSide.Read(buf)
	if k > 0 && !s.queueStreamData(st, buf[:k]) {
		return false, err
	}

	return true, err
}

// downlinkAllowance blocks until the stream may read something; false if
// the stream or session is closed.
func (s *session) downlinkAllowance(st *stream) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if st.closed || s.isClosed {
			return 0, false
		}

		allowance := min(st.sendCredit, DataChunk, s.downlinkHeadroomLocked())
		if allowance > 0 {
			return int(allowance), true
		}

		s.mu.Unlock()

		select {
		case <-st.downWake:
		case <-st.done:
		}

		s.mu.Lock()
	}
}

// queueStreamData queues data read from a stream, waiting while budgets
// refuse it. false if the stream or session is closed.
func (s *session) queueStreamData(st *stream, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if st.closed || s.isClosed {
			return false
		}

		if s.queueDownlinkLocked(Frame{Type: FrameData, StreamID: st.id, Payload: data}, pendingDownlink) {
			st.sendCredit -= int64(len(data))

			return true
		}

		s.mu.Unlock()

		timer := time.NewTimer(downlinkRetryInterval)

		select {
		case <-st.downWake:
		case <-st.done:
		case <-timer.C:
		}

		timer.Stop()
		s.mu.Lock()
	}
}

func wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// --- uplink ----------------------------------------------------------------

type simStream struct {
	live   bool
	window int64
}

// beginUpload takes the session's single uplink slot. It is taken before
// the request body is read, so that one session never buffers more than one
// uplink body at a time. Every successful call must be paired with
// endUpload.
func (s *session) beginUpload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case s.isClosed:
		return errSessionClosed
	case s.upBusy:
		return errConcurrent
	}

	s.upBusy = true

	return nil
}

// endUpload releases the slot taken by beginUpload.
func (s *session) endUpload() {
	s.mu.Lock()
	s.upBusy = false
	s.mu.Unlock()
}

// processUp applies one uplink batch. It returns the acknowledged sequence
// number. The caller must hold the uplink slot (beginUpload).
func (s *session) processUp(seq uint64, body []byte) (uint64, error) {
	s.mu.Lock()

	if s.isClosed {
		s.mu.Unlock()

		return 0, errSessionClosed
	}

	s.activity = s.now()
	digest := sha256.Sum256(body)

	switch {
	case seq == 0:
		return 0, s.protocolErrorLocked("zero sequence")
	case seq == s.lastSeq:
		if digest != s.lastDigest {
			return 0, s.protocolErrorLocked("retry with a different body")
		}

		s.mu.Unlock()

		return seq, nil
	case seq != s.lastSeq+1:
		return 0, s.protocolErrorLocked("unexpected sequence")
	}

	frames, err := ParseFrames(body, s.limits.MaxFramePayload)
	if err != nil {
		return 0, s.protocolErrorLocked("cannot parse batch")
	}

	charged, upBytes, upItems, err := s.validateLocked(frames)
	if err != nil {
		return 0, s.protocolErrorLocked(err.Error())
	}

	if upItems > 0 && !s.chargeLocked(pendingUplink, upBytes, upItems) {
		s.mu.Unlock()

		return 0, errBackpressure
	}

	s.lastSeq = seq
	s.lastDigest = digest

	toStart := s.applyLocked(frames, charged)
	s.mu.Unlock()

	for _, st := range toStart {
		s.startStream(st)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosed {
		return 0, errSessionClosed
	}

	return seq, nil
}

// protocolErrorLocked closes the session and unlocks the mutex.
func (s *session) protocolErrorLocked(reason string) error {
	s.logger.Info("protocol violation: " + reason)
	s.closeLocked()
	s.mu.Unlock()

	return fmt.Errorf("%w: %s", errSessionProtocol, reason)
}

// validateLocked checks the whole batch against a snapshot of the stream
// state, without side effects. It returns the uplink budget the batch needs
// and which frames (DATA to a live stream) it is charged for.
func (s *session) validateLocked(frames []Frame) ([]bool, int64, int, error) { //nolint: cyclop
	sim := map[uint32]*simStream{}
	lookup := func(id uint32) *simStream {
		if v, ok := sim[id]; ok {
			return v
		}

		if st := s.streams[id]; st != nil {
			v := &simStream{live: true, window: st.receiveWindow}
			sim[id] = v

			return v
		}

		if _, ok := s.tombstones[id]; ok {
			v := &simStream{}
			sim[id] = v

			return v
		}

		return nil
	}

	var (
		upBytes int64
		upItems int
		charged = make([]bool, len(frames))
	)

	for i, f := range frames {
		if err := f.ValidateClientShape(); err != nil {
			return nil, 0, 0, fmt.Errorf("bad frame shape type=0x%02x id=%d", byte(f.Type), f.StreamID)
		}

		if f.Type == FramePong {
			continue
		}

		st := lookup(f.StreamID)

		switch f.Type { //nolint: exhaustive
		case FrameOpen:
			if st != nil {
				return nil, 0, 0, fmt.Errorf("OPEN on used id %d", f.StreamID)
			}

			sim[f.StreamID] = &simStream{live: true, window: InitialStreamWindow}

			continue
		}

		if st == nil {
			return nil, 0, 0, fmt.Errorf("frame type=0x%02x on unknown id %d", byte(f.Type), f.StreamID)
		}

		if !st.live {
			continue
		}

		switch f.Type { //nolint: exhaustive
		case FrameData:
			n := int64(len(f.Payload))
			if n > st.window {
				return nil, 0, 0, fmt.Errorf("receive window exceeded on id %d", f.StreamID)
			}

			st.window -= n
			upBytes += n + queueItemCost
			upItems++
			charged[i] = true
		case FrameClose:
			st.live = false
		}
	}

	return charged, upBytes, upItems, nil
}

// applyLocked applies a validated and budgeted batch. It returns streams
// that must be handed to serve once the lock is released.
func (s *session) applyLocked(frames []Frame, charged []bool) []*stream {
	var toStart []*stream

	for i, f := range frames {
		if s.isClosed {
			break
		}

		st := s.streams[f.StreamID]

		switch f.Type { //nolint: exhaustive
		case FrameOpen:
			if st := s.openStreamLocked(f.StreamID); st != nil {
				toStart = append(toStart, st)
			}
		case FrameData:
			if st == nil {
				// tombstoned, or refused at OPEN: drop and give back budget.
				if charged[i] {
					s.releaseLocked(pendingUplink, int64(len(f.Payload))+queueItemCost, 1)
				}

				continue
			}

			st.upQueue = append(st.upQueue, append([]byte(nil), f.Payload...))
			st.receiveWindow -= int64(len(f.Payload))
			wake(st.upWake)
		case FrameWindow:
			if st == nil {
				continue
			}

			n, _ := WindowAmount(f.Payload)
			st.sendCredit = min(st.sendCredit+int64(n), math.MaxUint32)
			wake(st.downWake)
		case FrameClose:
			if st != nil {
				s.closeStreamLocked(st, false, true)
			}
		}
	}

	return toStart
}

// --- downlink poll ---------------------------------------------------------

// poll is a downlink long poll. cursor is the client's acknowledgement: the
// cursor of the last batch it received. It returns the next batch (or nil
// if there is nothing to send) and the cursor the client has to send next.
// The returned body is shared with a possible retry and must not be
// modified.
//
// A non-empty body comes with the session's single downlink write slot,
// taken under the same lock that hands the body out; the caller must
// release it with endDownload once the body is written (or failed). While
// the slot is held, poll refuses with errConcurrent before acknowledging
// anything, so a batch stays charged to the budgets until its write ends.
// A parked poll does not hold the slot: a newer poll still supersedes it.
func (s *session) poll(ctx context.Context, cursor uint64, longPoll time.Duration) ([]byte, uint64, error) {
	s.mu.Lock()

	switch {
	case s.isClosed:
		s.mu.Unlock()

		return nil, 0, errSessionClosed
	case s.downBusy:
		s.mu.Unlock()

		return nil, 0, errConcurrent
	}

	s.activity = s.now()

	switch {
	case s.unacked != nil && cursor == s.downCursor-1:
		// the previous response was lost: replay it verbatim
		body, next := s.unackedBody, s.downCursor
		s.downBusy = true
		s.mu.Unlock()

		return body, next, nil
	case cursor != s.downCursor:
		return nil, 0, s.cursorErrorLocked()
	case s.unacked != nil:
		s.ackLocked()
	}

	if s.waiter != nil {
		close(s.waiter) // newest poll wins
	}

	mine := make(chan struct{})
	s.waiter = mine

	timer := time.NewTimer(longPoll)
	defer timer.Stop()

	for {
		switch {
		case s.isClosed:
			s.dropWaiterLocked(mine)
			s.mu.Unlock()

			return nil, 0, errSessionClosed
		case s.waiter != mine:
			s.mu.Unlock()
			// we may have consumed a notification meant for the new waiter
			wake(s.downlinkNotify)

			return nil, cursor, nil
		case len(s.downlink) > 0:
			s.dropWaiterLocked(mine)
			body, next := s.cutBatchLocked()
			s.downBusy = true
			s.activity = s.now()
			s.mu.Unlock()

			return body, next, nil
		}

		s.mu.Unlock()

		select {
		case <-s.downlinkNotify:
		case <-mine:
		case <-s.done:
		case <-ctx.Done():
			s.mu.Lock()
			s.dropWaiterLocked(mine)
			s.mu.Unlock()

			return nil, 0, ctx.Err() //nolint: wrapcheck
		case <-timer.C:
			s.mu.Lock()

			if s.waiter == mine && !s.isClosed {
				s.dropWaiterLocked(mine)
				next := s.downCursor
				s.activity = s.now()
				s.mu.Unlock()

				return nil, next, nil
			}

			continue // superseded or closed meanwhile: handled above
		}

		s.mu.Lock()
	}
}

// endDownload releases the downlink write slot that poll handed out with a
// non-empty body.
func (s *session) endDownload() {
	s.mu.Lock()
	s.downBusy = false
	s.mu.Unlock()
}

func (s *session) dropWaiterLocked(mine chan struct{}) {
	if s.waiter == mine {
		s.waiter = nil
	}
}

// cursorErrorLocked closes the session and unlocks the mutex.
func (s *session) cursorErrorLocked() error {
	s.logger.Info("protocol violation: unexpected downlink cursor")
	s.closeLocked()
	s.mu.Unlock()

	return errCursor
}

// ackLocked releases the budget of the acknowledged batch, exactly once.
func (s *session) ackLocked() {
	var (
		bytes [pendingClasses]int64
		items [pendingClasses]int
	)

	for _, it := range s.unacked {
		bytes[it.class] += it.bytes
		items[it.class] += it.items
	}

	s.unacked = nil
	s.unackedBody = nil

	for class := range pendingClasses {
		s.releaseLocked(pendingClass(class), bytes[class], items[class])
	}

	for _, st := range s.streams {
		wake(st.downWake)
	}
}

// cutBatchLocked takes up to MaxBatchFrames pending frames that fit into
// CarrierBatchBytes (at least one) into a new unacknowledged batch.
func (s *session) cutBatchLocked() ([]byte, uint64) {
	var (
		n    int
		size int
	)

	for _, it := range s.downlink {
		frameSize := FrameHeaderSize + len(it.frame.Payload)
		if n == MaxBatchFrames || (n > 0 && size+frameSize > s.limits.CarrierBatchBytes) {
			break
		}

		n++
		size += frameSize
	}

	items := s.popDownlinkLocked(n)
	body := make([]byte, 0, size)

	for _, it := range items {
		body = AppendFrame(body, it.frame.Type, it.frame.StreamID, it.frame.Payload)
	}

	s.downCursor++
	s.unacked = items
	s.unackedBody = body

	return body, s.downCursor
}
