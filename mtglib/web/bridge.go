package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const bridgeNonceBytes = 18

// bridgeDisabledFeatures are the browser features the bridge page turns off.
// The page only runs fetch and postMessage, so it needs none of them: no
// device or sensor access, no media capture or playback, no credentials, no
// clipboard and no display or window control.
var bridgeDisabledFeatures = []string{
	// capture and media
	"camera", "microphone", "display-capture", "speaker-selection",
	"autoplay", "encrypted-media", "picture-in-picture", "fullscreen",
	// location and sensors
	"geolocation", "accelerometer", "gyroscope", "magnetometer",
	"ambient-light-sensor", "xr-spatial-tracking",
	// devices
	"usb", "serial", "hid", "bluetooth", "midi", "gamepad",
	// payments and credentials
	"payment", "publickey-credentials-get", "publickey-credentials-create",
	"otp-credentials", "identity-credentials-get",
	// system and window
	"screen-wake-lock", "idle-detection", "window-management", "local-fonts",
	"clipboard-read", "clipboard-write", "web-share", "keyboard-map",
	// tracking and storage
	"browsing-topics", "attribution-reporting", "storage-access",
}

// permissionsPolicy disables every feature of bridgeDisabledFeatures.
var permissionsPolicy = func() string {
	parts := make([]string, len(bridgeDisabledFeatures))
	for i, f := range bridgeDisabledFeatures {
		parts[i] = f + "=()"
	}

	return strings.Join(parts, ", ")
}()

var (
	errBridge = errors.New("cannot render bridge page")

	bridgePlaceholders = []string{
		"__NONCE__", "__RELAY_BASE__", "__BOOTSTRAP__", "__BATCH_LIMIT__", "__LONG_POLL_MS__",
	}
)

// bridgePage is a rendered bridge page together with its per-response
// security policy.
type bridgePage struct {
	Body  []byte
	Nonce string
	CSP   string
}

// renderBridge renders the bridge page for one bootstrap token. longPollMs
// is the server long-poll timeout; the page bounds its downlink requests by it.
func renderBridge(hostname, bootstrap string, batchBytes, longPollMs int) (bridgePage, error) {
	return renderBridgeTemplate(bridgeTemplate, hostname, bootstrap, batchBytes, longPollMs)
}

func renderBridgeTemplate(tmpl, hostname, bootstrap string, batchBytes, longPollMs int) (bridgePage, error) {
	if hostname == "" {
		return bridgePage{}, fmt.Errorf("%w: empty hostname", errBridge)
	}

	if batchBytes <= 0 {
		return bridgePage{}, fmt.Errorf("%w: batch limit %d is not positive", errBridge, batchBytes)
	}

	if longPollMs <= 0 {
		return bridgePage{}, fmt.Errorf("%w: long poll %d ms is not positive", errBridge, longPollMs)
	}

	for _, p := range bridgePlaceholders {
		if !strings.Contains(tmpl, p) {
			return bridgePage{}, fmt.Errorf("%w: template has no %s", errBridge, p)
		}
	}

	raw := make([]byte, bridgeNonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return bridgePage{}, fmt.Errorf("%w: %w", errBridge, err)
	}

	nonce := base64.RawURLEncoding.EncodeToString(raw)

	// json.Marshal escapes <, > and & so values are safe inside <script>.
	relayBase, err := json.Marshal("https://" + hostname + "/")
	if err != nil {
		return bridgePage{}, fmt.Errorf("%w: %w", errBridge, err)
	}

	boot, err := json.Marshal(bootstrap)
	if err != nil {
		return bridgePage{}, fmt.Errorf("%w: %w", errBridge, err)
	}

	body := strings.NewReplacer(
		"__NONCE__", nonce,
		"__RELAY_BASE__", string(relayBase),
		"__BOOTSTRAP__", string(boot),
		"__BATCH_LIMIT__", strconv.Itoa(batchBytes),
		"__LONG_POLL_MS__", strconv.Itoa(longPollMs),
	).Replace(tmpl)

	for _, p := range bridgePlaceholders {
		if strings.Contains(body, p) {
			return bridgePage{}, fmt.Errorf("%w: %s survived substitution", errBridge, p)
		}
	}

	csp := strings.Join([]string{
		"default-src 'none'",
		"script-src 'nonce-" + nonce + "'",
		"connect-src 'self' wss://" + hostname,
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors http://127.0.0.1:*",
		"sandbox allow-same-origin allow-scripts",
	}, "; ")

	return bridgePage{Body: []byte(body), Nonce: nonce, CSP: csp}, nil
}

// writeBridge writes a rendered bridge page. X-Frame-Options is deliberately
// absent: the loopback parent frames the page (frame-ancestors governs it).
func writeBridge(w http.ResponseWriter, p bridgePage) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(p.Body)))
	h.Set("Content-Security-Policy", p.CSP)
	h.Set("Permissions-Policy", permissionsPolicy)
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-DNS-Prefetch-Control", "off")
	w.WriteHeader(http.StatusOK)
	w.Write(p.Body) //nolint: errcheck
}

// bridgeTemplate is the bridge page. It connects a Telegram client (an
// injected TelegramWebProxy object or a MessagePort from a loopback parent
// frame) to the relay API of this server.
const bridgeTemplate = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
'use strict';
(() => {
  // Substituted by the server.
  const RELAY_BASE = __RELAY_BASE__;
  const BOOTSTRAP = __BOOTSTRAP__;
  const BATCH_LIMIT = __BATCH_LIMIT__;
  const LONG_POLL_MS = __LONG_POLL_MS__;

  const FRAME_HEADER = 8;
  const MAX_FRAMES = 4096;
  const QUEUE_MAX_BYTES = 32 * 1024 * 1024;
  const QUEUE_MAX_ITEMS = 16384;
  const REQUEST_TIMEOUT_MS = 90000;
  // A parked poll lasts LONG_POLL_MS at most; past this margin it is dead.
  const POLL_TIMEOUT_MS = LONG_POLL_MS + 5000;
  const RETRY_BUDGET_MS = 90000;
  const RETRY_AFTER_CAP_MS = 30000;
  const BACKOFF_MIN_MS = 250;
  const BACKOFF_MAX_MS = 5000;
  const NETWORK_ATTEMPTS = 9;
  const FETCH_OPTIONS = {mode:'same-origin', credentials:'omit', cache:'no-store', redirect:'error', referrerPolicy:'no-referrer'};

  // The Android app passes its nonce in the fragment. Drop query and
  // fragment from the address right away.
  const fragment = /^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash);
  const androidNonce = fragment ? fragment[1] : null;
  history.replaceState(null, '', location.pathname);

  let app = null;             // attached boundary: {binary, control, close}
  let closed = false;
  let status = null;
  let helloSeen = false;
  let sessionToken = null;
  let downCursor = null;      // decimal string, echoed back verbatim
  let upSeq = 1;
  let upRunning = false;
  const upQueue = [];         // {data, ends, offset, next}
  let upQueueBytes = 0;
  const inflight = new Set(); // AbortControllers of running requests
  const sleepers = new Set(); // pending sleeps, released on close

  class ClosedError extends Error {}

  // ---- helpers -----------------------------------------------------------

  // frameEnds returns the end offset of every frame of a batch, or null if
  // the bytes are not a whole number of frames.
  function frameEnds(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const ends = [];
    let at = 0;
    while (at < bytes.length) {
      if (bytes.length - at < FRAME_HEADER) return null;
      const end = at + FRAME_HEADER + view.getUint32(at + 4);
      if (end > bytes.length) return null;
      ends.push(end);
      at = end;
    }
    return ends;
  }

  // toBytes returns a private copy of binary message data, or null.
  function toBytes(data) {
    if (data instanceof ArrayBuffer || Object.prototype.toString.call(data) === '[object ArrayBuffer]') {
      return new Uint8Array(data.slice(0));
    }
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
    }
    return null;
  }

  function parseCounter(value) {
    return value !== null && /^(0|[1-9][0-9]{0,19})$/.test(value) ? value : null;
  }

  function parseRetryAfter(value) {
    let ms = 1000;
    if (value !== null && /^[0-9]+$/.test(value.trim())) {
      ms = Number(value.trim()) * 1000;
    } else if (value !== null) {
      const at = Date.parse(value);
      if (!Number.isNaN(at)) ms = at - Date.now();
    }
    return Math.min(RETRY_AFTER_CAP_MS, Math.max(0, ms));
  }

  function backoff(failures) {
    const base = BACKOFF_MIN_MS * 2 ** (failures - 1);
    return Math.min(BACKOFF_MAX_MS, base * (1 + 0.25 * Math.random()));
  }

  function sleep(ms) {
    return new Promise((resolve) => {
      const sleeper = {resolve, id: 0};
      sleeper.id = setTimeout(() => { sleepers.delete(sleeper); resolve(); }, ms);
      sleepers.add(sleeper);
    });
  }

  // notify sends a control message to the app; best effort.
  function notify(msg) {
    if (!app) return;
    try { app.control(msg); } catch (e) { /* the app is gone */ }
  }

  function setStatus(state) {
    if (state === status) return;
    status = state;
    notify({t:'status', state});
  }

  function traffic(up, down) {
    notify({t:'traffic', up, down});
  }

  // run starts a runner; any failure other than our own close is fatal.
  function run(promise) {
    promise.catch(() => { if (!closed) fail(); });
  }

  // ---- messages from the app ---------------------------------------------

  function onAppMessage(data) {
    if (closed) return;
    const bytes = toBytes(data);
    if (bytes) {
      onAppBinary(bytes);
      return;
    }
    let msg = data;
    if (typeof data === 'string') {
      try { msg = JSON.parse(data); } catch (e) { return; }
    }
    if (msg && typeof msg === 'object' && msg.t === 'close') close(true);
  }

  function onAppBinary(bytes) {
    if (bytes.length === 0) return;
    if (!helloSeen) {
      helloSeen = true;
      run(openSession(bytes));
      return;
    }
    const ends = frameEnds(bytes);
    if (!ends || upQueue.length >= QUEUE_MAX_ITEMS || upQueueBytes + bytes.length > QUEUE_MAX_BYTES) {
      fail();
      return;
    }
    upQueue.push({data: bytes, ends, offset: 0, next: 0});
    upQueueBytes += bytes.length;
    startUplink();
  }

  // ---- boundary A: object injected by the Android app ---------------------

  function attachInjected(bridge) {
    app = {
      binary(bytes) {
        // One relay frame per message.
        let at = 0;
        for (const end of frameEnds(bytes)) {
          bridge.postMessage(bytes.slice(at, end).buffer);
          at = end;
        }
      },
      control(msg) { bridge.postMessage(JSON.stringify(msg)); },
      close() { bridge.onmessage = null; },
    };
    bridge.onmessage = (event) => onAppMessage(event ? event.data : undefined);
    bridge.postMessage(JSON.stringify({t:'tproxy-android-init', v:1, nonce: androidNonce}));
    setStatus('connecting');
  }

  // ---- boundary B: MessagePort from a loopback parent frame ---------------

  function onWindowMessage(event) {
    if (app || closed) return;
    if (parent === window || event.source !== parent) return;
    const data = event.data;
    if (!data || typeof data !== 'object') return;
    const keys = Object.keys(data);
    if (keys.length !== 2 || !keys.includes('t') || !keys.includes('v')) return;
    if (data.t !== 'tproxy-init' || data.v !== 1) return;
    if (!event.ports || event.ports.length !== 1) return;
    let origin;
    try { origin = new URL(event.origin); } catch (e) { return; }
    if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || origin.port === '') return;
    window.removeEventListener('message', onWindowMessage); // accept once
    attachPort(event.ports[0]);
  }

  function attachPort(port) {
    app = {
      binary(bytes) {
        // Whole batches; the buffer is ours, so transfer it.
        const whole = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
        const buffer = whole ? bytes.buffer : bytes.slice().buffer;
        port.postMessage(buffer, [buffer]);
      },
      control(msg) { port.postMessage(msg); },
      close() { port.onmessage = null; port.close(); },
    };
    port.onmessage = (event) => onAppMessage(event.data);
    setStatus('connecting');
  }

  // ---- HTTP --------------------------------------------------------------

  // exchange performs one request with fixed options and an abort timer.
  // A timeout rejects like a network error.
  async function exchange(method, path, headers, body, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    inflight.add(controller);
    try {
      const init = Object.assign({}, FETCH_OPTIONS, {method, headers, signal: controller.signal});
      if (body) init.body = body;
      const res = await fetch(RELAY_BASE + path, init);
      const data = new Uint8Array(await res.arrayBuffer());
      return {status: res.status, headers: res.headers, body: data};
    } finally {
      clearTimeout(timer);
      inflight.delete(controller);
    }
  }

  // request retries the byte-identical request: 503 after Retry-After,
  // network errors (timeouts included) with exponential backoff. The retry
  // budget starts at the first failure, not at the first attempt, so a
  // request that stalled until its abort timer can still be retried.
  async function request(method, path, headers, body, timeoutMs = REQUEST_TIMEOUT_MS) {
    let firstFailure = null;
    let failures = 0;
    for (;;) {
      if (closed) throw new ClosedError();
      let res;
      try {
        res = await exchange(method, path, headers, body, timeoutMs);
      } catch (err) {
        if (closed) throw new ClosedError();
        if (firstFailure === null) firstFailure = Date.now();
        failures++;
        if (failures >= NETWORK_ATTEMPTS) throw err;
        await waitRetry(firstFailure, backoff(failures));
        continue;
      }
      if (res.status === 503) {
        if (firstFailure === null) firstFailure = Date.now();
        await waitRetry(firstFailure, parseRetryAfter(res.headers.get('Retry-After')));
        continue;
      }
      if (status === 'reconnecting') setStatus(sessionToken ? 'connected' : 'connecting');
      return res;
    }
  }

  async function waitRetry(firstFailure, delay) {
    if (Date.now() - firstFailure + delay > RETRY_BUDGET_MS) throw new Error('retry budget exhausted');
    setStatus('reconnecting');
    await sleep(delay);
    if (closed) throw new ClosedError();
  }

  // ---- session -----------------------------------------------------------

  // The first binary message is HELLO; the answer carries WELCOME.
  async function openSession(hello) {
    const res = await request('POST', 'api/v1/session', {
      'Authorization': 'Bearer ' + BOOTSTRAP,
      'Content-Type': 'application/octet-stream',
    }, hello);
    if (res.status !== 200 || res.headers.get('X-Carrier-Mode') !== 'https') {
      throw new Error('session refused');
    }
    const token = res.headers.get('X-Session-Token');
    const cursor = parseCounter(res.headers.get('X-Down-Cursor'));
    if (!token || cursor === null || res.body.length === 0 || !frameEnds(res.body)) {
      throw new Error('bad session answer');
    }
    sessionToken = token;
    downCursor = cursor;
    app.binary(res.body);
    setStatus('connected');
    startUplink(); // flush what was queued meanwhile
    run(downlink());
  }

  // ---- uplink: one request in flight -------------------------------------

  function startUplink() {
    if (upRunning || closed || !sessionToken || upQueue.length === 0) return;
    upRunning = true;
    run(uplink());
  }

  async function uplink() {
    while (!closed && upQueue.length > 0) {
      const body = takeBatch();
      const seq = String(upSeq);
      const res = await request('POST', 'api/v1/up', {
        'Authorization': 'Bearer ' + sessionToken,
        'Content-Type': 'application/octet-stream',
        'X-Up-Seq': seq,
      }, body);
      if (res.status !== 204 || res.headers.get('X-Up-Ack') !== seq) throw new Error('uplink refused');
      traffic(body.length, 0);
      upSeq++;
    }
    upRunning = false;
  }

  // takeBatch joins whole queued items within the byte and frame limits. A
  // first item that does not fit alone is cut at a frame boundary.
  function takeBatch() {
    const parts = [];
    let size = 0;
    let frames = 0;
    while (upQueue.length > 0) {
      const item = upQueue[0];
      const restBytes = item.data.length - item.offset;
      const restFrames = item.ends.length - item.next;
      if (size + restBytes <= BATCH_LIMIT && frames + restFrames <= MAX_FRAMES) {
        parts.push(item.data.subarray(item.offset));
        size += restBytes;
        frames += restFrames;
        upQueue.shift();
        upQueueBytes -= restBytes;
        continue;
      }
      if (parts.length > 0) break;
      let next = item.next;
      while (next < item.ends.length && next - item.next < MAX_FRAMES &&
             item.ends[next] - item.offset <= BATCH_LIMIT) {
        next++;
      }
      if (next === item.next) throw new Error('frame exceeds the batch limit');
      const end = item.ends[next - 1];
      parts.push(item.data.subarray(item.offset, end));
      size = end - item.offset;
      upQueueBytes -= size;
      item.offset = end;
      item.next = next;
      break;
    }
    const body = new Uint8Array(size);
    let at = 0;
    for (const part of parts) {
      body.set(part, at);
      at += part.length;
    }
    return body;
  }

  // ---- downlink: a single long poll --------------------------------------

  async function downlink() {
    while (!closed) {
      const res = await request('POST', 'api/v1/down', {
        'Authorization': 'Bearer ' + sessionToken,
        'X-Down-Cursor': downCursor,
      }, null, POLL_TIMEOUT_MS);
      if (res.status === 204) continue;
      const next = parseCounter(res.headers.get('X-Down-Cursor'));
      if (res.status !== 200 || res.body.length === 0 || next === null || !frameEnds(res.body)) {
        throw new Error('downlink refused');
      }
      traffic(0, res.body.length);
      app.binary(res.body);
      downCursor = next;
    }
  }

  // ---- teardown ----------------------------------------------------------

  function fail() {
    if (closed) return;
    setStatus('failed');
    notify({t:'close'});
    close(true);
  }

  function close(notifyServer) {
    if (closed) return;
    closed = true;
    window.removeEventListener('message', onWindowMessage);
    for (const controller of inflight) controller.abort(); // the parked poll too
    inflight.clear();
    for (const sleeper of sleepers) {
      clearTimeout(sleeper.id);
      sleeper.resolve();
    }
    sleepers.clear();
    if (notifyServer && sessionToken) {
      try {
        fetch(RELAY_BASE + 'api/v1/session', Object.assign({}, FETCH_OPTIONS, {
          method: 'DELETE',
          keepalive:true,
          headers: {'Authorization': 'Bearer ' + sessionToken},
        })).catch(() => {});
      } catch (e) { /* the page is going away */ }
    }
    if (app) {
      try { app.close(); } catch (e) { /* already closed */ }
    }
  }

  // ---- start -------------------------------------------------------------

  window.addEventListener('pagehide', () => close(true));

  const injected = globalThis.TelegramWebProxy;
  if (androidNonce && injected && typeof injected.postMessage === 'function') {
    attachInjected(injected);
  } else {
    window.addEventListener('message', onWindowMessage);
  }
})();
</script>
</body>
</html>
`
