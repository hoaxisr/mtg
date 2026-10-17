# WEB proxy support for mtg — design

Date: 2026-10-16. Branch: `web-proxy` (based on `routebox-multi-secret` +
upstream `master`).

## 1. Intent

Telegram is introducing a new proxy type, **WEB**, whose reference server is
[telegramdesktop/tproxy-server](https://github.com/telegramdesktop/tproxy-server)
(protocol in its `PROTOCOL.md`, "WEB proxy protocol v1"). The client keeps
running ordinary MTProxy (obfuscated2, `dd` padded-intermediate) but tunnels
every connection through a hidden WebView that speaks plain HTTPS/WSS to what
is, to any observer, a real website with a real certificate. The server
demultiplexes the logical streams and feeds each into an MTProxy.

mtg today speaks only Fake TLS (`ee` secrets). This design adds the WEB
transport to mtg **as a library feature first** (`mtglib`), with the `mtg`
CLI as one consumer, so embedders such as
[hoaxisr/routebox](https://github.com/hoaxisr/routebox) (a panel that runs
mtglib in-process with one secret per user) can offer WEB proxies without a
second binary.

Why now: Fake TLS is increasingly fingerprinted and probed; WEB removes TLS
impersonation entirely (real TLS, real browser engine, real site). telemt
already ships an implementation; tproxy-server is Go, so mtg is the natural
Go home for it.

## 2. Goals

1. A WEB-capable Telegram client (Telegram Desktop today; Android/iOS proofs
   of concept) configured with `hostname` + mtg's secret connects through an
   mtg instance and reaches Telegram, interoperating with the **unmodified**
   client and the v1 wire protocol.
2. Exported library API: an `http.Handler` an embedder can mount anywhere,
   plus one new `mtglib.Proxy` entry point. No WEB logic hidden under
   `mtglib/internal`.
3. Works with both the single-secret upstream model (`ProxyOpts.Secret`) and
   the multi-secret fork model (`ProxyOpts.Secrets`), with per-secret
   attribution (`EventClientMatched`) for WEB streams.
4. The `mtg` CLI gets a `[web]` config section, prints WEB links in
   `mtg access`, and serves Fake TLS and WEB from one process.
5. Unauthenticated requests are indistinguishable from the operator's public
   website; authenticated-but-malformed requests fail locally with an
   uncacheable 404, exactly as the reference does.
6. Existing mtg defenses apply per WEB stream: allowlist/blocklist,
   concurrency limit, anti-replay, idle timeout, events/stats.

## 3. Non-goals (phase 1)

- Carrier modes other than `https`. `websocket`, `https-lanes`,
  `websocket-lanes` are phase 2+. The carrier layer is an interface so they
  can be added without touching session semantics.
- TLS termination inside mtg. A reverse proxy (Caddy, nginx, HAProxy,
  sing-box) owns the certificate and forwards plain HTTP to mtg on loopback,
  exactly like tproxy-server and telemt. In-process autocert is a possible
  later step.
- Base path deployments (`/<slug>/`, "v2" capability context, `0x70`-marked
  link secrets). Phase 2. The routing layer must not assume `/` is the only
  possible base, but phase 1 implements root only.
- telemt's extensions (server-side carrier negotiation, recovery endpoint,
  diagnostic sideband). Not part of the Telegram protocol.
- Telegram "ad tag" / promoted channels. mtglib has never supported it.
- Upstreaming to 9seconds/mtg as part of this work. Designed to be
  upstreamable (see §5.11), not blocked on it.

## 4. Anti-goals

- **Copying tproxy-server source.** The repository has no license file. Its
  protocol document and test vectors are the spec; its Go and JavaScript are
  reference reading only. Everything here is an independent implementation.
- A WEB stream that bypasses mtg's defenses. If a stream could skip the
  blocklist or concurrency cap, the feature is a regression.
- Leaking secrets or bearer tokens into logs. mtg's structured logger must
  never see a bridge URL, `Authorization` header, or token.
- A design that forces RouteBox to stop/start the whole proxy to add a WEB
  profile *more often than it already does for Fake TLS*. (It already
  rebuilds on roster changes; WEB must be no worse.)

## 5. Decisions

### 5.1 Package layout

```
mtglib/
  proxy.go            + ServeWebConn (one new exported method, see 5.3)
  web/                NEW, exported
    handler.go        Handler: http.Handler, Options, NewHandler, Shutdown
    profile.go        Profile, capability derivation, WebSecret, Link
    bridge.go         bridge page template + CSP/headers
    token.go          bootstrap/session tokens
    session.go        Session, stream state, flow control
    carrier_https.go  serialized HTTPS carrier
    carrier.go        carrier interface (future: websocket, lanes)
    frame.go          shared frame codec
    limits.go         Limits, rate buckets, Manager
    public.go         public-site helpers (NewPublicUpstream, NewPublicDir)
    streamconn.go     virtual essentials.Conn per stream
internal/config       + Web section
internal/cli          + wiring in run_proxy.go, access.go
```

`mtglib/web` imports `mtglib` (for `Secret`, `Proxy`, `Logger`,
`EventStream`), never the reverse, so upstream mtglib stays unaware of WEB
except for `ServeWebConn`.

### 5.2 Secrets and capabilities

mtg secrets are `ee || key(16) || host`. The WEB protocol wants a 16-byte
MTProxy secret, keeping a `dd` prefix when padding is used. mtg's obfuscated2
handshake accepts only the `dd dd dd dd` padded-intermediate transport
(`mtglib/obfuscation/handshake_frame.go:38`), so:

- **WEB secret shown to users** = `dd || key`, hex (34 chars). Never the
  `plain` 16-byte form: a `plain` client would use an unpadded transport mtg
  rejects.
- **Capability** = `base64url_nopad(HMAC-SHA256(key = dd||key,
  msg = "tdesktop-web-proxy-bridge-v1\n" + hostname))`. The published test
  vector (`proxy.example.com`, `dd000102…0f` →
  `IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA`) is a unit test.
- `hostname` for WEB is a **separate** setting from the Fake TLS fronting
  host in the secret. They may be equal (one domain serving both) or differ.
  Lowercase ASCII/IDNA A-label, no port.
- One `Profile` per secret: `{Index int, Secret mtglib.Secret, Limits}`.
  `Index` is the position in `ProxyOpts.Secrets` (0 for single-secret), so
  `EventClientMatched` works unchanged. Capabilities are precomputed; bridge
  lookup is a constant-time compare against each profile.
- Link: `tg://webproxy?server=<hostname>&secret=<dd-hex>`, and the
  `https://t.me/webproxy?…` form, both printed by `mtg access` and returned
  by `web.Link`.

### 5.3 Core entry point: `ServeWebConn`

```go
// ServeWebConn admits a connection whose TLS has already been terminated
// elsewhere and whose bytes begin with the obfuscated2 handshake. It applies
// the allowlist, blocklist and concurrency limit exactly as Serve does,
// then dispatches to the worker pool and returns without blocking.
func (p *Proxy) ServeWebConn(conn essentials.Conn, secretIdx int) error
```

Errors: `ErrIPBlocklisted`, `ErrIPNotAllowlisted`, `ErrConcurrencyLimited`,
`ErrSecretIndex`, `ErrProxyClosed`. The web handler turns any error into a
`CLOSE` for that stream; the session stays up.

The worker body is a variant of `ServeConn` that:

1. creates the stream context, sends `EventStart` with the client IP;
2. **skips** `doFakeTLSHandshake` and the doppelganger wrapper (both exist
   only to make Fake TLS look right);
3. reads the 64-byte obfuscated2 frame under the handshake deadline, runs the
   anti-replay check on that frame (`AntiReplayCache.SeenBefore`) — this is
   the WEB equivalent of the TLS session-id check — then completes the
   obfuscated handshake with the profile's key;
4. sets `secretIdx`, emits `EventClientMatched`;
5. continues with `doTelegramCall` and `relay.Relay` with the idle tracker,
   unchanged.

A replayed or malformed handshake closes the stream (the client sees
`CLOSE`); there is no domain-fronting fallback inside a WEB stream because
the public site already answered the HTTP layer.

`ServeConn` and the new worker share the post-handshake tail; refactor so
the tail is one function rather than duplicated.

### 5.4 Virtual connection per stream

Each `OPEN` creates a `streamConn` implementing `essentials.Conn`, built on
`net.Pipe()` (synchronous, deadline-aware) plus two pump goroutines owned by
the session:

- **uplink pump**: pops queued client `DATA` chunks for the stream and
  writes them to the pipe; after each successful write, credits the client
  with a `WINDOW` of that size (grants reflect bytes delivered, as the
  reference does).
- **downlink pump**: reads from the pipe up to `min(sendCredit, 64 KiB,
  downlink budget headroom)` and queues a `DATA` frame; blocks when credit or
  budget is zero.

`RemoteAddr()` returns a synthesized `*net.TCPAddr{IP: clientIP, Port: 0}`
so `streamContext.ClientIP()` works. `CloseRead`/`CloseWrite` map to
`Close` (the protocol has no half-close). `Close` from the proxy side queues
`CLOSE` to the client; `CLOSE` from the client closes the pipe, which makes
the relay exit and `EventFinish` fire.

The uplink queue is bounded by the protocol's 4 MiB receive window; the
downlink queue by the client's 4 MiB credit plus the session batch budget.
No unbounded buffers.

### 5.5 Session and `https` carrier semantics

Behaviour follows PROTOCOL.md and matches the reference where the spec is
silent:

- `POST /api/v1/session`: bootstrap bearer, body = exactly one `HELLO`
  (≤ 64 bytes), returns `X-Session-Token`, `X-Down-Cursor: 0`,
  `X-Carrier-Mode: https`, body `WELCOME`. Bootstrap consumption is
  atomic; a replay with identical body returns the same session token;
  capacity exhaustion returns `503 Retry-After: 1` without consuming the
  bootstrap.
- `POST /api/v1/up`: `X-Up-Seq` starting at 1; next-sequence or
  byte-identical retry of the last (SHA-256 digest compare); whole batch
  validated against a snapshot before any frame is applied; uplink budget
  shortfall or a concurrent parse → `503 Retry-After: 1` with nothing
  applied; `204 X-Up-Ack`.
- `POST /api/v1/down`: one parked poll; newest poll wins, the superseded one
  returns `204` with its own cursor; cursor == last unacked base replays the
  same body; cursor == current acks and releases budget; long-poll timeout
  25 s → `204`; batches ≤ 4096 frames and ≤ `carrier_batch_bytes` (2 MiB).
- `DELETE /api/v1/session`: idempotent; closed tokens remembered for the
  bootstrap lifetime so a late DELETE is 204, not 404.
- Frames: `OPEN` on a live or tombstoned id, or `DATA/WINDOW/CLOSE` on an
  unknown id = protocol failure (session closed); on a tombstoned id = silently
  accepted. 4096 tombstones. `OPEN` rejected by any limit → `CLOSE` for that
  id only.
- Pending accounting: each queued item costs `bytes + 256` and one item;
  control frames (`WINDOW`, `CLOSE`) draw on a reserved partition so data
  pressure can never block them.
- Session liveness: `lastActivity` on every request; cleanup loop every 30 s
  expires bootstraps (2 min) and sessions silent longer than
  `reconnect_grace` (2 min).

Carrier abstraction: `type carrier interface` with `attach(session)` and the
per-mode HTTP/WS handling; `https` is the only implementation in phase 1.

### 5.6 Tokens

Same construction as the reference (it is sound and the layout is opaque to
clients): 32 bytes = 12 random ‖ 4-byte AES-128 filter tag ‖ 16-byte
truncated HMAC-SHA256 over `"tproxy-server-token-v1\0" ‖ kind ‖ nonce`;
43-char base64url. Verification is constant time; map keys are SHA-256 of
the decoded token.

**Signing key** (my call, differs from the reference): `Options.TokenKey`
is optional. When absent, the key is derived as
`HMAC-SHA256(profiles[0].Secret.Key, "mtg-web-token-key-v1")`. mtg has no
state directory, the proxy secret is already persistent and private, and the
derivation is one-way, so this gives restart-stable tokens with zero new
operational burden. Operators who rotate secrets implicitly rotate token
keys, which is the desired outcome.

Secret scanning of unauthenticated request metadata (URL, Host, headers)
for stray tokens/capabilities, with the filter tag to skip HMACs, is kept:
it is what makes "authentic token on the wrong path → local 404, never the
decoy" possible.

### 5.7 Bridge page

An independently written page that satisfies the same contract the client
depends on (`PROTOCOL.md` §"Client-to-bridge boundary" and the reference
JS as behavioural reference, not source):

- `GET /?bridge=<43 chars>` only, exact path, exact single query parameter;
  response is `text/html`, `Cache-Control: no-store`, nonce-CSP exactly as
  specified (`default-src 'none'`, `script-src 'nonce-…'`,
  `frame-ancestors http://127.0.0.1:*`, `sandbox allow-same-origin
  allow-scripts`), `Referrer-Policy: no-referrer`, nosniff,
  `X-DNS-Prefetch-Control: off`, Permissions-Policy denying everything.
- Supports both boundaries: injected `TelegramWebProxy` object with the
  `#android=<nonce>` fragment and `{"t":"tproxy-android-init","v":1,"nonce"}`
  handshake, and the loopback-parent `MessagePort` boundary
  (`{t:'tproxy-init',v:1}` from an `http://127.0.0.1:<port>` origin, once).
- `history.replaceState` to drop query and fragment; `{t:'status',state}`,
  `{t:'traffic',up,down}`, `{t:'close'}` control messages; first binary
  message is HELLO and triggers session creation; batching to ≤ 4096
  frames / ≤ batch limit; retry rules (503 honours `Retry-After`, 90 s
  budget, ≤ 9 attempts on network errors, exponential backoff to 5 s);
  `pagehide` → DELETE with `keepalive`.
- Fetch options: `same-origin`, `credentials: 'omit'`, `cache: 'no-store'`,
  `redirect: 'error'`, `referrerPolicy: 'no-referrer'`.

The page is a Go `const` template with `__NONCE__`, `__RELAY_BASE__`,
`__BOOTSTRAP__`, `__BATCH_LIMIT__` substitutions, validated at render time.
Its JS is the compatibility risk of the project and gets a dedicated test
harness (see §7).

### 5.8 Public site (decoy) and request routing

`Options.Public http.Handler` is mandatory in the library. Two constructors
are provided: `NewPublicUpstream(url)` (an `httputil.ReverseProxy` to a
loopback/private HTTP origin, preserving `Host` and path, stripping
hop-by-hop headers) and `NewPublicDir(dir)` (static files, `index.html`,
custom `404.html`, no directory listings). The CLI exposes both as
`public-upstream` / `public-dir`, exactly one required.

Routing decision per request, in order:

1. No authentic capability/token anywhere in request metadata → `Public`.
   This includes random bearers, cookies, wrong paths — the decoy answers
   everything it would answer for a stranger.
2. Authentic secret present → `Cache-Control: no-store` on every response;
   `Host` must be the configured hostname (or `hostname:443`), else 404.
3. Exact API path with exact method, no query string, at most one
   `Authorization`, no `Cookie` → carrier handler.
4. Exact `GET /` with raw query exactly `bridge=<43 canonical chars>` →
   bridge page with a fresh bootstrap.
5. Anything else → local uncacheable 404.

Client IP: `RemoteAddr` must be within `Options.TrustedProxies` (default:
loopback only); `X-Forwarded-For` must contain exactly one parseable IP,
else 404. Bootstraps are not bound to the IP; sessions are accounted
against the IP that creates them.

Body rules: create ≤ 64 bytes; up ≤ `max_body_bytes` (2 MiB) via
`http.MaxBytesReader`, non-empty, `Content-Type: application/octet-stream`
exactly; down/DELETE require an empty body and no `Content-Type`; header
integers are canonical decimal (no `+`, no leading zeros).

### 5.9 Limits and admission

Defaults copied from the reference and overridable globally and per
profile (profile values may only lower the global ones):

| limit | default |
|---|---:|
| max_sessions_global / per_ip | 128 / 0 (off) |
| max_streams_global / per_session | 4096 / 128 |
| new_sessions per minute / burst | 600 / 128 |
| new_streams per minute / burst | 6000 / 512 |
| max_bootstraps_global, per minute / burst | 512, 1200 / 256 |
| max_pending per session / global | 32 MiB / 512 MiB |
| max_pending_items per session / global | 16384 / 262144 |
| carrier_batch_bytes, max_body_bytes, max_frame_payload | 2 MiB, 2 MiB, 1 MiB |
| long_poll, reconnect_grace, bootstrap_lifetime | 25 s, 2 m, 2 m |

`NewHandler` refuses a configuration whose per-session control reserve ×
`max_sessions_global` leaves no data headroom, as the reference does.

mtg's own `Concurrency` (worker pool) is a second, independent cap that
`ServeWebConn` enforces; pool overload is reported as
`EventConcurrencyLimited` and the stream gets `CLOSE`.

### 5.10 Observability

Per stream, the existing events fire unchanged: `EventStart` (with client
IP), `EventClientMatched`, `EventTraffic`, `EventFinish`,
`EventReplayAttack`, `EventConcurrencyLimited`, `EventIPBlocklisted`,
`EventIPAllowlisted`. RouteBox's connection list and per-client traffic
therefore work for WEB streams without changes.

New in `mtglib/web`: `Handler.Stats()` returning live sessions, live
streams, pending bytes/items, totals (sessions/streams created, streams
rejected, limit hits, bytes up/down). Prometheus/statsd export of these is
left to the CLI's existing `stats` package and is phase 2.

Logging: the handler receives an `mtglib.Logger`; it logs event classes and
counts only — never URLs, headers, tokens, or capabilities.

### 5.11 CLI integration

`[web]` section in the TOML config (all optional, section disabled unless
`enabled = true`):

```toml
[web]
enabled = true
bind-to = "127.0.0.1:3130"       # plain HTTP, loopback; reverse proxy in front
hostname = "proxy.example.com"   # public HTTPS hostname, lowercase
public-upstream = "http://127.0.0.1:3000"   # or:
# public-dir = "/srv/site"
trusted-proxies = ["127.0.0.0/8", "::1/128"]
# token-key = "<base64 32 bytes>"  # optional, see §5.6
[web.limits]
# max-sessions = 128 ...
```

`run_proxy.go` builds `web.NewHandler` with `Profiles` derived from
`conf.Secret` (index 0), starts an `http.Server` on `bind-to`, and shuts it
down before `proxy.Shutdown()`. Reverse-proxy snippets for Caddy and nginx
go in `example.config.toml` comments and the README.

`mtg access` adds a `web` object: hostname, web secret (dd-hex), `tg://` and
`t.me` links, QR code URLs. `mtg doctor` gains a check that `hostname`
resolves to this host and that `https://hostname/` serves a 200 (phase 2
if time is short).

The `.github/workflows/sync-upstream.yml` inherited from the RouteBox fork
is removed on this branch; it targets a different branch and repository.

### 5.12 Compatibility with upstream and the multi-secret fork

- `ServeWebConn(conn, secretIdx)` compiles against upstream with
  `secretIdx == 0` and against the fork with any index. `web.Profile.Index`
  is the only place the fork's model shows.
- `go.mod` keeps `module github.com/9seconds/mtg/v2`. RouteBox-style
  consumers use a `replace` directive, as RouteBox already does.
- New dependency: none expected in phase 1 (stdlib `net/http`,
  `crypto/*`, `net/http/httputil`). WebSocket (phase 2) will use
  `golang.org/x/net/websocket` or `gorilla/websocket`; decide then.

## 6. Constraints

- Go 1.25 (`go.mod` on this branch); CI runs `go test ./...`, golangci-lint
  with the repo's config, and fuzz tests exist for codecs — new codecs get
  fuzz tests too.
- The build/test cycle in this environment occasionally hits a Fedora Go
  compiler crash; `go build -p 1` works around it. Not a code concern.
- The protocol is proof-of-concept stage and telemt has already extended
  it; implement v1 exactly and keep extensions out until Telegram adopts
  them.
- Client availability for end-to-end testing: Telegram Desktop builds with
  WEB support exist; Android is experimental; iOS supports only `https`
  (which is why `https` is phase 1).

## 7. Testing strategy

1. **Unit**: frame codec (+fuzz), capability vectors from PROTOCOL.md, token
   encode/verify/tag/constant-time, canonical header parsing, routing table
   (table-driven over method/path/query/header combinations → public,
   bridge, API, local-404), limits/rate buckets.
2. **Session semantics**: table tests driving `Session` directly: seq
   retry/idempotency, 503 paths, newest-poll-wins, cursor replay/ack,
   window accounting in both directions, tombstones, OPEN rejection →
   CLOSE, control-frame reserve under data pressure.
3. **Handler**: `httptest.Server` with a fake `Public` handler, asserting
   byte-level response parity between "stranger" requests to the handler
   and to the public handler alone (the probing-resistance property), and
   the bridge CSP/header set.
4. **End to end (Go)**: a Go "bridge client" that speaks the `https`
   carrier like the page does, an `mtglib.Proxy` whose `Network` is a
   test-only implementation redirecting every `Dial` to an in-process fake
   Telegram DC (a listener that answers the server side of obfuscated2 via
   `obfuscation.Obfuscator{}.ReadHandshake` and echoes or scripts replies),
   and `obfuscation.Obfuscator.SendHandshake` as the client-side encoder.
   `ProxyOpts.DCOverrides` is a dead option ("OBSOLETE and DEPRECATED") and
   is **not** revived: the redirect lives in the test's `Network`, so
   mtglib's public surface gains nothing beyond `ServeWebConn` (my call).
   Asserts bytes round-trip, WINDOW grants, CLOSE propagation, replay
   rejection, blocklist enforcement, `EventClientMatched` with the right
   index.
5. **Bridge JS**: a headless-browser test is not in CI. Provide a
   `contrib/web-bridge-harness/` loopback page (the "loopback parent
   boundary") that embeds the bridge in an iframe and exercises
   HELLO/OPEN/DATA/CLOSE against a local handler, runnable manually in a
   browser; plus a manual test plan against Telegram Desktop.

## 8. Phasing

- **Phase 1 (this design)**: `mtglib/web` with `https` carrier,
  `ServeWebConn`, CLI `[web]` section, `mtg access` links, docs.
- **Phase 2**: `websocket` carrier; base path; Prometheus/statsd for WEB;
  `mtg doctor` WEB checks.
- **Phase 3**: lane carriers; telemt-style negotiation only if clients ship
  it; optional in-process autocert.

## 9. Left to the builder

- Internal goroutine/channel structure of `Session` beyond the invariants
  in §5.5 (the reference uses one mutex per session and no per-session
  goroutines; a channel-based design is equally acceptable if the
  invariants hold).
- Whether `streamConn` uses `net.Pipe` or a custom deadline-aware buffer,
  provided the bounds in §5.4 hold.
- Exact error types and logger field names, following existing mtglib
  conventions.
- Static-site edge cases (range requests, conditional GETs): use stdlib
  `http.ServeContent` behaviour; do not reimplement.
- Test fixture layout.

## 10. Risks

- **Bridge JS compatibility** with real Telegram Desktop is only provable
  against the client. Mitigation: the loopback harness, and testing early
  with a Desktop build before polishing the server.
- **Protocol churn**: v1 labels are "frozen" but the reference is a PoC.
  Mitigation: all wire constants in one file; carrier interface.
- **Reference license**: unlicensed source. Mitigation: no copying; the
  design lists behaviours, not code; reviewers check for verbatim JS.
- **Probing parity**: any header, timing, or status difference between the
  decoy and the handler's "stranger" path is a distinguisher. Mitigation:
  parity tests (§7.3) and a rule that the handler adds no headers on the
  public path.
