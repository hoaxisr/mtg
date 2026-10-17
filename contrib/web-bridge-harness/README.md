# WEB bridge harness

A single static page that plays the role of a Telegram client against a
deployed mtg WEB proxy. It embeds the bridge page of your site in an
iframe, hands it a `MessageChannel` port, sends a relay handshake and logs
everything that comes back. Use it to check a deployment without Telegram.

The bridge accepts a parent only from `http://127.0.0.1:<port>`, so serve
the page locally:

```console
$ cd contrib/web-bridge-harness
$ python3 -m http.server 8099 --bind 127.0.0.1
```

## Browser steps

1. Open `http://127.0.0.1:8099/` in a browser.
2. Enter the hostname (`web.hostname`) and the secret (`web.secret` from
   `mtg access`, the `dd...` hex string).
3. Press Connect.

Every log line starts with a timestamp. Messages from the bridge are
logged as JSON objects, binary batches as a list of frames. The log should
show, in order (timestamps left out):

```
loading https://mtg.example.com/?bridge=...
init sent
sent HELLO
sent OPEN 1 + DATA 1 (64 zero bytes)
{"t":"status","state":"connecting"}
frames (8 bytes):
  WELCOME stream=0 len=0
{"t":"status","state":"connected"}
frames (20 bytes):
  WINDOW stream=1 len=4
  CLOSE stream=1 len=0
```

WELCOME is delivered before the `connected` status: it is the answer to
the session request, and the bridge reports `connected` right after
handing it over. `CLOSE stream=1` is expected: the harness sends `OPEN 1`
and a `DATA 1` with 64 zero bytes, which is not a valid obfuscated2
handshake, so the relay closes the stream. The `WINDOW` grant for the 64
bytes may come in the same batch, in its own batch, or not at all.
`{"t":"traffic",...}` lines may appear in between. The server
never sends PING.

## Telegram Desktop

1. Add a proxy of type WEB with the hostname and the `dd...` secret from
   `mtg access`. The client should connect.
2. Stop the reverse proxy. The client should show that it is reconnecting.
3. Start it again. The client should recover within the reconnect grace
   (`web.timeouts.reconnect-grace`, 2 minutes by default).
