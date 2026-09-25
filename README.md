# NetLink

A lightweight, security-first network communication library for games and
general-purpose client/server applications. It gives you UDP's speed with
TCP's optional guarantees: choose reliability and ordering per message,
on independent channels, over an encrypted connection, with C/C++,
Python, Go, and Rust all speaking the same wire protocol.

```
 C / C++ client  |                                   | Go server
 Python client   |---  same wire protocol  ----------|
 Rust client     |    (UDP, X25519 + AES-256-GCM)    | Rust / C server
```

## Why one C core instead of a reimplementation per language

Netcode bugs are usually protocol bugs, and protocol bugs multiply when
the same handshake/reliability/encryption logic is written N times in N
languages that inevitably drift out of sync. NetLink implements the
protocol exactly once, in portable C11 (`src/`), and every language
binding (`bindings/`) is a thin wrapper over its stable C ABI
(`include/netlink.h`). A Python client and a Go server are running the
literal same reliability and crypto code, not two independent
reimplementations that happen to agree today.

## Features

- **Reliable and unreliable packets, chosen per send.** Four delivery
  modes, picked per message: `UNRELIABLE`, `UNRELIABLE_SEQUENCED`
  (unreliable but stale/out-of-order packets are dropped so you only ever
  see newer data), `RELIABLE_UNORDERED`, `RELIABLE_ORDERED`.
- **In-order delivery** on any channel via `RELIABLE_ORDERED`, backed by a
  proper sliding-window ack/retransmit scheme with a reorder buffer.
- **Automatic fragmentation and reassembly** for messages up to 256 KB,
  with defensive bounds on every attacker-controlled field (fragment
  count, index, claimed size) so a malformed or hostile peer can't grow
  memory unboundedly.
- **Multiple independent channels** (up to 32) per connection -- each
  `(channel, delivery mode)` pair has its own sequence space, so a
  reliable channel stalled on a lost packet never head-of-line-blocks an
  unrelated channel.
- **Encryption by default:** X25519 ephemeral key exchange, HKDF-SHA256
  key derivation, AES-256-GCM authenticated encryption for every packet
  after the handshake, and a 64-wide sliding-window replay guard. See
  [Security model](#security-model) below.
- **A connect handshake resistant to trivial spoofing/flooding:** a
  server doesn't allocate full connection state until a client echoes
  back a server-issued cookie, proving it can receive at its claimed
  source address; handshake processing is additionally rate-limited.
- **WebSocket transport** (`NL_TRANSPORT_WEBSOCKET`): TCP + RFC6455
  framing for browser/interoperability use. The same encrypted NetLink
  handshake and reliability machinery rides inside binary WebSocket
  messages (one NL packet per frame); the opening HTTP upgrade is a
  standards-compliant `Sec-WebSocket-Key`/`Accept` exchange (SHA-1 via
  OpenSSL EVP). LAN discovery remains UDP-only and returns
  `NL_ERR_UNSUPPORTED` on WebSocket endpoints. Fixed path `/`.
- **Native thread safety.** The library runs its own background I/O
  thread; `nl_send()` and `nl_poll_event()` can be called from any thread
  without external locking.
- **IPv6 support**, dual-stack where the OS allows it (implemented and
  exercised in code review; see [Testing](#testing) for why it couldn't
  be run to completion in this project's own dev sandbox).
- **LAN server discovery** via UDP broadcast (probe/reply with server
  name and player count) -- handy for local multiplayer without a
  master server. UDP transport only.
- **C/C++, Python, Go, and Rust bindings** over one shared protocol
  implementation.
- **Real RTT measurement and adaptive retransmission timing.** Every
  clean (never-retransmitted) ack produces an RTT sample, smoothed via
  the Jacobson/Karels algorithm (RFC 6298 -- the same one TCP uses) into
  a retransmission timeout that adapts to actual path conditions instead
  of a fixed guess.
- **Fast retransmit.** When the ack bitmap shows a packet is missing
  while several newer ones have already arrived (the same signal behind
  TCP's "three duplicate acks"), the missing packet is retransmitted
  immediately rather than waiting for the RTO timer -- often shaving a
  full RTT or more off recovery latency.
- **Per-peer statistics** (`nl_peer_stats`): packets/bytes sent and
  received, retransmit count, duplicate/replayed packets rejected,
  smoothed RTT, RTT variance, and current RTO -- useful for in-game
  diagnostics or server-side monitoring.
- **Congestion control (packet-based Reno)** on reliable sends: a
  congestion window grows under acks (slow start, then congestion
  avoidance), collapses on loss (RTO or fast-retransmit signal), and
  parks further sends until budget reopens -- so multiple clients
  sharing a link don't all blast at once.
- **Flow control.** Every DATA header carries a u16 receive window; a
  sender defers when the peer's window is full and resumes as the peer
  consumes queued events (distinct from congestion control, which asks
  what the *network* can handle).
- **Per-connection rate limiting.** Optional token-bucket limit on
  payload bytes/second (`config.max_send_bytes_per_sec`); retransmits
  and keepalives are exempt so loss recovery is never starved.
- **Priority/QoS per send.** `nl_send_ex(..., priority)` parks messages
  when the send window is closed and flushes highest-priority first as
  budget opens (stable FIFO within a priority).
- **Protocol capability negotiation in the handshake.** Peers advertise
  an `NL_CAP_*` bitmask in REQUEST/CHALLENGE; the negotiated set is the
  intersection of both sides' sets (`nl_peer_capabilities`), so future
  optional features don't require moving every peer in lockstep.

### Deliberately not included (see [Roadmap](#roadmap--known-limitations))

- **WebRTC.** A correct, secure WebRTC implementation (ICE + DTLS + SCTP)
  is a large undertaking in its own right, and a half-correct one is a
  security liability. Not included; see the roadmap.

## Quick start

### C

```c
#include <netlink.h>

nl_config_t cfg;
nl_config_default(&cfg);

nl_address_t addr = {0};
strcpy(addr.host, "0.0.0.0");
addr.port = 9000;

nl_endpoint_t *server;
nl_server_create(&addr, &cfg, &server);

while (1) {
    nl_event_t ev;
    if (!nl_poll_event(server, &ev, 100)) continue;
    if (ev.event_type == NL_EVENT_DATA) {
        nl_send(server, ev.peer, ev.channel, NL_RELIABLE_ORDERED, ev.data, ev.data_len); // echo
    }
}
```

See `examples/echo_server.c` and `examples/echo_client.c` for complete,
runnable programs.

### WebSocket transport

Set `cfg.transport = NL_TRANSPORT_WEBSOCKET` on both ends. The server
listens on TCP and speaks the RFC6455 opening handshake; the client
dials out, upgrades, then runs the normal encrypted NetLink handshake.
One NetLink packet rides in each binary WebSocket message.

```c
nl_config_t cfg;
nl_config_default(&cfg);
cfg.transport = NL_TRANSPORT_WEBSOCKET;

nl_address_t addr = {0};
strcpy(addr.host, "0.0.0.0");
addr.port = 9001;

nl_endpoint_t *server;
nl_server_create(&addr, &cfg, &server);
/* ... same nl_poll_event / nl_send loop as UDP ... */
```

See `tests/integration/test_websocket_integration.c` for a full
client/server example. Path is fixed to `/`; LAN discovery is UDP-only
and returns `NL_ERR_UNSUPPORTED` on WebSocket endpoints.

### Python

```python
import netlink

server = netlink.Server("0.0.0.0", 9000)
for event in server.events(timeout=1.0):
    if event.type == netlink.EventType.DATA:
        server.send(event.peer, event.channel, event.data)
```

See `bindings/python/README.md`.

### Go / Rust

```go
// see bindings/go/README.md
server, err := netlink.NewServer("0.0.0.0", 9000, netlink.NewConfig())
```

```rust
// see bindings/rust/README.md
let mut client = Client::new(Config::default())?;
let peer = client.connect("127.0.0.1", 9000)?;
```

Both are covered by real-socket tests (`make test-bindings`).

### All four client/server combinations

For step-by-step instructions on running C/C++ or Python clients against
Go or Rust servers (and vice versa), see
[CROSS_LANGUAGE_TESTING.md](CROSS_LANGUAGE_TESTING.md).

## Building

Requires a C11 compiler, pthreads, and OpenSSL's `libcrypto` (the only
external dependency -- no vendored crypto, no bundled dependencies).

```sh
# Most Linux distros, once libssl-dev (or equivalent) is installed and
# pkg-config knows about it:
make

# If pkg-config doesn't have a libcrypto.pc (as in this project's own dev
# sandbox), point at it explicitly:
make CRYPTO_CFLAGS="-I/path/to/openssl/include" CRYPTO_LIBS="-L/path/to/openssl/lib -lcrypto"

# macOS with Homebrew OpenSSL:
make CRYPTO_CFLAGS="-I$(brew --prefix openssl)/include" CRYPTO_LIBS="-L$(brew --prefix openssl)/lib -lcrypto"
```

This produces `build/libnetlink.a` (static) and `build/libnetlink.so`
(shared, for FFI bindings). `make test` builds and runs the full test
suite; `make examples` builds the example programs.

## Architecture

```
include/netlink.h    Public C ABI -- every binding targets exactly this.
src/
  protocol.h          Wire format constants (packet types, header layout).
  byteorder.h          Alignment-safe big-endian read/write helpers.
  seqbuf.{h,c}          Sequence buffers: send-ring (retransmission),
                          recv-dedupe (ack bitfield), reorder-ring (ordering).
  fragment.{h,c}         Message fragmentation / reassembly with DoS bounds.
  crypto.{h,c}            X25519, HKDF-SHA256, AES-256-GCM, replay window
                           -- all via OpenSSL EVP, no hand-rolled primitives.
  websocket.{h,c}         RFC6455 framing + HTTP upgrade handshake (pure
                           logic, unit-tested; no sockets). Endpoint.c
                           drives it for NL_TRANSPORT_WEBSOCKET.
  channel.{h,c}            Per-(channel, delivery mode) "lane" state,
                            tying seqbuf + fragment together. Pure logic,
                            no sockets -- independently unit-testable by
                            feeding one instance's output into another's.
  connection.{h,c}          One established peer: encryption keys, the
                            channel array, and the mutex that makes
                            concurrent nl_send()/receive/tick safe.
  endpoint.c                  Sockets, the background I/O thread, the
                               connect handshake state machine, the
                               connection table, and the event queue --
                               i.e. everything in include/netlink.h.
```

### Delivery modes and channels

A `channel_id` (0-31) selects an independent lane with its own sequence
space; a `nl_delivery_t` chosen per `nl_send()` call selects the
guarantee for that specific message. The two compose freely: you might
send player input reliably-ordered on channel 0, chat messages
reliably-ordered on channel 1 (so a lost chat message never delays input,
or vice versa), and position updates unreliable-sequenced on channel 2.

### Security model

- **Handshake:** ephemeral X25519 key pairs are generated fresh for every
  connection (no long-term keys, so there's nothing to leak that would
  expose past sessions). The server issues a cookie
  (`HMAC-SHA256(server_secret, client_address || client_pubkey || nonces)`)
  in its challenge; the client must echo it back before the server
  allocates full connection state (channels, buffers) -- this bounds the
  resource cost of a spoofed-source-address flood to a cheap HMAC and a
  small, capped pending-connection table, not a full connection object.
  Handshake packet processing is additionally rate-limited
  (200/second/endpoint by default).
- **Encryption:** every packet after the handshake (`DATA`, `KEEPALIVE`,
  `DISCONNECT`, and the handshake-completion packet) is AES-256-GCM
  encrypted and authenticated. Header fields needed for routing
  (connection id, nonce counter) are sent as AEAD associated data --
  authenticated but not encrypted, and tampering with them is detected
  just like tampering with the ciphertext.
- **Nonces:** built as `per-direction-random-salt XOR packet-counter`,
  guaranteeing uniqueness for the life of a connection without needing to
  transmit a full 96-bit nonce per packet.
- **Replay protection:** a 64-wide sliding-window guard (the same
  approach IPsec/DTLS use) rejects replayed ciphertexts independent of
  which channel/delivery-mode they claim to belong to -- this matters
  specifically for `UNRELIABLE` traffic, which intentionally skips the
  channel-level dedupe that reliable modes get, and would otherwise be
  replayable. The window is only updated *after* successful
  authentication, so a forged packet can't "burn" a valid counter value
  and cause a legitimate later packet to be wrongly rejected (see
  `src/crypto.c`'s `nl_replay_window_would_accept` vs `_check` split).
- **Fragmentation bounds:** fragment count, index, and total reconstructed
  size are all validated against fixed maximums before any allocation;
  concurrent in-flight reassemblies are capped with oldest-eviction, and
  incomplete ones expire after 8 seconds -- an attacker sending bogus
  fragment headers can't grow memory without bound.
- **What this is not:** a defense against on-path (man-in-the-middle with
  active packet control) attackers beyond what authenticated encryption
  provides, or a substitute for validating application-level input.
  "Security first" here means the transport layer doesn't hand an
  attacker cheap wins (spoofing, replay, resource-exhaustion via
  malformed packets) -- it doesn't mean the library has been through a
  professional security audit. Treat it accordingly for anything
  high-stakes, and see [Contributing](CONTRIBUTING.md) if you find a gap.

## Testing

This is the one section worth reading before trusting any of the above:
what's claimed here is exactly what was verified, not more.

**Built, run, and passing in this project's own development
environment** (a Linux container with a C toolchain, OpenSSL, Python, Go,
and Rust):

- 156 C test cases across unit tests (`tests/test_seqbuf.c`,
  `test_crypto.c`, `test_fragment.c`, `test_channel.c`,
  `test_connection.c`, `test_network_simulation.c`,
  `test_websocket.c`: 128 cases) and real-socket integration tests
  (`tests/integration/test_integration.c`: 23 cases,
  `tests/integration/test_websocket_integration.c`: 5 cases), all clean
  under AddressSanitizer + UndefinedBehaviorSanitizer -- no leaks, no UB.
- `test_network_simulation.c` specifically drives thousands of messages
  through a simulated bad network (configurable packet loss, jitter/
  reordering, duplication) and verifies `RELIABLE_ORDERED` delivery stays
  complete and correctly ordered throughout -- including at 20% loss and
  25% duplication -- rather than only ever being exercised over perfect
  localhost conditions.
- The integration tests spin up **real client and server endpoints
  communicating over actual loopback UDP sockets**, covering: the full
  encrypted handshake, capability negotiation, all four delivery modes,
  fragmentation of a 5000-byte and 40000-byte messages (the latter
  exceeds the initial congestion window and exercises continuation
  parking + standalone acks), one-way reliable traffic (server never
  app-sends -- acks must ride on `NL_PKT_ACK`), multiple independent
  channels, graceful disconnect, LAN discovery (including random-nonce
  rejection and `from_address` taken from the socket source),
  server-full denial, and the previously untested introspection APIs
  (`nl_peer_address`, `nl_peer_rtt_ms`, `nl_peer_count`, `nl_send_ex`,
  `nl_error_string`).
- The **Python bindings** (9 tests), **Go bindings** (10 tests via
  `go test`), and **Rust bindings** (11 tests via `cargo test`), each
  exercised the same way: real `Server` + `Client` over real sockets,
  covering echo, all delivery modes, fragmentation, priority/`send_ex`,
  peer stats/capabilities/RTT/count, disconnect, and server-full denial.
  Run them all with `make test-bindings`.
- The **example C programs** (`echo_server`/`echo_client`), run as two
  independent OS processes exchanging messages across three channels and
  delivery modes. The Go and Rust example servers also build in CI.
- The **WebSocket transport** (`NL_TRANSPORT_WEBSOCKET`): HTTP upgrade +
  encrypted NetLink handshake + reliable/unordered/unreliable delivery
  and fragmentation over loopback TCP, exercised by
  `tests/integration/test_websocket_integration.c` (5 cases).

**Written but not compiled/run here, for lack of toolchain/platform:**

- **Windows** (`socket_compat.h`'s `_WIN32` branch uses documented Winsock
  APIs following the same logic as the POSIX path, but wasn't build-tested
  here).
- **IPv6**, at the integration-test level: the code path is implemented
  (dual-stack binding, `AF_INET6` throughout) and the test for it exists
  and runs, but if the host has no IPv6 support the test skips itself
  rather than reporting a false pass. If you run the test suite somewhere
  with IPv6 available, please check that it actually passes.

If you build and test any of the above in an environment that has the
missing pieces, a PR (or even just an issue reporting the result) is a
genuinely valuable contribution.

## Roadmap / known limitations

- **Coarse-grained connection locking.** A single mutex guards the whole
  connection table and is held for the duration of any operation on a
  connection found through it (see the comment at the top of
  `src/endpoint.c`). This is what makes connection lifetime safe without
  reference counting, but it means two unrelated connections can't send
  concurrently at full parallelism. Fine for the connection counts a
  typical game server or general-purpose service needs; a sharded lock
  or RCU-style scheme would remove the bottleneck for very high
  connection counts.
- **No connection migration.** If a client's address changes mid-connection
  (e.g. a NAT rebind or network switch), the connection times out rather
  than following the new address, unlike e.g. QUIC.
- **WebRTC** is not implemented (see Features). WebSocket transport is
  implemented but currently binds a fixed path (`/`) and does not
  advertise LAN discovery over the WebSocket endpoint.
- **Connection table lookup is O(n)** (linear scan, bounded at 512
  connections internally). Fine for small-to-medium deployments; a hash
  map would be a straightforward improvement for large ones.

### Future work

An external review of this project suggested a substantial list of
additions to move NetLink from "capable UDP library" toward something
closer to a full modern transport (connection migration, an RPC layer,
built-in serialization, compression, and more -- plus infrastructure
like CMake, fuzzing, and multi-OS CI). It's good feedback and most of it
is a genuine gap, not a nitpick. Implementing all of it to the same
tested standard as the rest of this project is realistically a much
larger effort than one pass. RTT-based adaptive retransmission, fast
retransmit, per-peer stats, a randomized network-condition test harness
(see Testing above), and the core transport slice (congestion control,
flow control, per-connection rate limiting, priority/QoS, capability
negotiation) have been implemented and tested. What's left, roughly in
priority order:

1. **Connection migration** -- `PATH_CHALLENGE`/`PATH_RESPONSE` so a
   client changing networks (mobile Wi-Fi <-> cellular, NAT rebind)
   doesn't need a full reconnect, QUIC-style.
2. **Expanded/range-based ACKs** -- the current 32-bit ack bitmap works
   well for the loss patterns tested above, but wider bitmaps or explicit
   ranges would help on very high-latency/lossy links.
3. **An optional RPC layer** with request/response semantics, and
   **built-in (optional, separate-from-core) serialization**.
4. **Compression** (compress-then-encrypt, never the reverse).
5. Smaller infrastructure: a C++ RAII wrapper, CMake alongside the
   Makefile, a pkg-config `.pc` file, fuzzing (libFuzzer/AFL++) on the
   packet-parsing paths, Windows/macOS/Go/Rust CI, and benchmarks.

If you'd like to tackle any of these, see [CONTRIBUTING.md](CONTRIBUTING.md)
-- a PR for a single item, with its own tests, is much easier to review
(and much more likely to actually be correct) than one that tries to do
several at once.

## License

MIT -- see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Changelog

### 1.1.1 (2026-09-25)

**Fixed**

- `gofmt` violations in the Go binding (`netlink.go`) and the Go
  example (`examples/echo_server/main.go`) that made editors' Go
  linters (e.g. nvim-lint) report a parser error. Formatting only --
  no behavior change; `go vet` and `go test` still pass.
- `.gitignore` pattern for the Go example build output narrowed to the
  binary path so the `examples/echo_server/` directory stays tracked.

**Changed**

- `Makefile` dist/pkg-config targets now read a single `VERSION`
  variable instead of hardcoding the release string.

### 1.1.0 (2026-09-25)

**Added**

- WebSocket transport (`NL_TRANSPORT_WEBSOCKET`): TCP + RFC6455 framing
  with a real HTTP upgrade handshake (`Sec-WebSocket-Key`/`Accept`,
  SHA-1 via OpenSSL EVP) and the existing encrypted NetLink protocol
  inside binary frames (one NL packet per frame). 18 unit tests in
  `tests/test_websocket.c`; 5 loopback integration tests in
  `tests/integration/test_websocket_integration.c`. Path fixed to `/`;
  LAN discovery is UDP-only and returns `NL_ERR_UNSUPPORTED` on
  WebSocket endpoints.
- Integration tests for the previously untested public C APIs:
  `nl_peer_address`, `nl_peer_rtt_ms`, `nl_peer_count`, `nl_send_ex`
  (priority + error paths), and `nl_error_string` (all codes).
- Go binding tests (`bindings/go/netlink_test.go`, 10 real-socket
  tests): echo, all delivery modes, fragmentation, `SendEx` priority,
  peer stats/capabilities/RTT/count, disconnect, server-full denial,
  duplicate-connect rejection, error formatting.
- Rust binding tests (`bindings/rust/tests/integration.rs`, 11
  real-socket tests + doctest) covering the same surface as Go.
- Python binding tests for `peer_rtt_ms`, `peer_count`, and
  `nl_error_string` (9 tests total, runnable without pytest).
- `make test-bindings` target: runs Python + Go + Rust binding tests
  against the freshly built library.

**Changed**

- Go and Rust bindings built, vetted, and passing tests for the first
  time; both can be exercised with `make test-bindings`.
- CI: `go-bindings` and `rust-bindings` jobs are no longer
  `continue-on-error`; they run `go test` / `cargo test` (plus example
  builds) and fail the build on regressions.
- cgo link flags now embed an rpath to `build/`, so `go test` finds
  `libnetlink.so` without extra environment variables.
- README, CONTRIBUTING, and `CROSS_LANGUAGE_TESTING.md` updated to
  reflect the verified Go/Rust status and new test counts.

### 1.0.0 (2026-09-24)

First stable release. Library version is **1.0.0**
(`NL_VERSION_MAJOR/MINOR/PATCH`, `nl_version_string()`, Python
`__version__` / `version()`, `Cargo.toml`, `pyproject.toml`). Wire
protocol is **`NL_PROTOCOL_VERSION` 3**.

Code review pass over the 0.1.0 core; all findings fixed with regression
tests (`make` warning-free, `make test` green under ASan/UBSan). Wire
format changed: **`NL_PROTOCOL_VERSION` bumped to 3** (see below).

Second review pass (same day): fixed one-way-reliable delivery (no
standalone acks -- receiver had nothing to piggyback on), peer-rwnd
accounting for in-flight bytes, send-ring overwrite of unacked slots,
backoff overflow on long give-up paths, discovery random nonces +
`from_address` provenance, handshake/discovery flood rate limits, and
several smaller correctness/docs gaps. Protocol bumped **2 → 3**. New
regression tests: large reliable messages (40 KB / 100 KB), continuation
parking under ring pressure, one-way reliable over simulated and real
sockets, send-ring overwrite refusal, discovery nonce capture over a
real loopback probe, and Python `send_ex`/peer-stats coverage.

Core transport slice: congestion control, flow control, per-connection
rate limiting, priority/QoS per send, and handshake capability
negotiation -- each with regression tests.

- **Congestion control (packet-based Reno).** Reliable sends are gated
  by a congestion window (initial 10 packets) that grows on acks and
  collapses on loss (RTO → cwnd=1; fast-retransmit → cwnd=ssthresh).
  Sends that exceed the window park in the deferred queue and flush when
  budget reopens.
- **Flow control.** DATA headers now carry a u16 receive window (wire
  format: `NL_DATA_HEADER_SIZE` 11 → 13). A sender defers when
  `peer_rwnd` is exhausted; the receiver releases the charge as the
  application consumes events via `nl_poll_event`. `nl_channel_*` and
  `nl_send_ring_ack` gained out-params for the newly-acked count and
  advertised window.
- **Per-connection rate limiting.** `config.max_send_bytes_per_sec`
  (0 = unlimited) drives a token bucket with a 1 s burst cap; failed
  window checks never steal tokens; retransmits/keepalives bypass the
  limiter.
- **Priority/QoS.** New `nl_send_ex(..., priority)` (and
  `NL_PRIORITY_*` constants). Deferred messages are sorted descending by
  priority (stable FIFO within a priority) and flushed highest-first as
  window/rate budget opens. Bounds: 128 messages / 64 KB per connection;
  overflow returns `NL_ERR_QUEUE_FULL`.
- **Capability negotiation.** REQUEST and CHALLENGE carry a u32
  `NL_CAP_*` bitmask (`NL_CAP_FLOW_CONTROL`, `NL_CAP_PRIORITY`,
  `NL_CAP_RATE_LIMIT`); both sides store the intersection and expose it
  via `nl_peer_capabilities`. `NL_CAP_FLOW_CONTROL` is always forced on.
  Wire sizes: REQUEST 64 → 68 bytes, CHALLENGE 67 → 69.
- **Standalone ACKs (protocol v3).** New encrypted `NL_PKT_ACK` packet so
  reliable traffic flowing one way (client → server with no reverse
  application data) still gets acks without waiting for a piggyback
  opportunity. Discovery probe nonces are now random (never zero) rather
  than a counter, so an off-path guesser can't forge a valid reply.
  **`NL_PROTOCOL_VERSION` bumped 2 → 3** for these wire changes.
- **Handshake retransmission.** `CONNECT_REQUEST`, `CONNECT_CHALLENGE`,
  and `CONNECT_ACCEPTED` are now retried on a 250 ms timer with a finite
  budget (`NL_ACCEPT_RETRIES` for the final accept), instead of a single
  fire-and-forget send that left a lost packet stalling until idle
  timeout. Duplicate in-flight `REQUEST`s re-send the cached `CHALLENGE`
  rather than colliding on the pending table; `DENY` tears down a
  half-open client connection cleanly.
- **`UNRELIABLE_SEQUENCED` + fragmentation.** The stale-drop gate was
  applied per fragment sequence number, so a reordered earlier fragment
  was dropped and the message never reassembled. The gate now runs once
  per complete message (against that message's highest fragment seq);
  every fragment reaches reassembly first.
- **Reassembly expiry on every tick.** `nl_channel_tick` now calls
  `nl_reassembly_expire` on each lane, so incomplete messages are
  reclaimed after `NL_REASSEMBLY_TIMEOUT_MS` (8 s) instead of only under
  slot-eviction pressure.
- **`encryption_enabled = false` rejected.** There is no cleartext mode;
  `nl_server_create`/`nl_client_create` return `NL_ERR_UNSUPPORTED`
  rather than silently encrypting (or shipping a protocol hole).
- **Discovery hardening.** Replies must echo the most recent probe's
  random nonce (delayed/forged replies are dropped); the event's
  `from_address` comes from the packet's socket source, not the
  attacker-controlled body. Discovery has its own rate-limit budget
  (200/s/endpoint), separate from the handshake limiter, so a flood of
  probes can't starve connect attempts. Handshake and discovery
  processing are rate-limited so response floods can't spin the I/O
  thread.
- **`max_connections` clamped** to the hard internal cap (512) at
  endpoint create, so discovery advertises the real limit instead of a
  value that would pass REQUEST-time checks and then fail silently at
  slot allocation.
- **Duplicate `nl_connect` rejected.** A second connect to the same
  address while one is in flight or established returns
  `NL_ERR_ALREADY_CONNECTED` instead of colliding on pending-table
  lookups.
- **`server_name` copied at create.** The endpoint owns a copy of
  `config.server_name`; clobbering the caller's buffer after
  `nl_server_create` no longer changes what discovery reports.
- **Endpoint failure cleanup.** All create failure paths (resolve,
  socket, bind, I/O thread) free via `endpoint_free` — sockets, pending
  entries, connection table, queue, mutexes, and the server secret —
  instead of leaking a partial endpoint.
- **Dead pending state removed.** `PENDING_CLIENT_AWAIT_ACCEPTED` is now
  released/teardown correctly on confirm, deny, and expiry (including
  destroying half-open client connections so `CONNECT_FAILED` is not
  delivered twice).
- **Binding ABI fix.** Python's `_Config` and Rust's `nl_config_t`
  mirror were missing the three new `nl_config_t` fields added above,
  so `nl_config_default` wrote past the end of the binding's struct
  (stack corruption / SIGSEGV at teardown in the Python CI job). Both
  mirrors now match C's layout (56 bytes); Go uses the real C header
  via cgo and was unaffected.
- **Regression tests** for the above: version string matching
  `NL_VERSION_*`, sequenced out-of-order fragments,
  channel-tick reassembly expiry, ACCEPTED retransmit budget,
  `encryption_enabled` rejection, duplicate connect, discovery wrong
  nonce + rate limit (raw-socket injection, works without broadcast),
  `max_connections` clamp, `server_name` copy, congestion-window gating
  and loss collapse, peer-window park/resume, rwnd wire round-trip,
  rate-limit defer + recovery, priority flush order, deferred-queue
  full, capability store, and handshake capability intersection
  (integration, real sockets).
