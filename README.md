# NetLink

A lightweight, security-first network communication library for games and
general-purpose client/server applications. It gives you UDP's speed with
TCP's optional guarantees: choose reliability and ordering per message,
on independent channels, over an encrypted connection, with C/C++,
Python, Go, and Rust all speaking the same wire protocol.

```
 C / C++ client  |                                   | Go server
 Python client   |---  same wire protocol  ----------|
 Rust client     |    (UDP, X25519 + AES-256-GCM)     | Rust / C server
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
- **Native thread safety.** The library runs its own background I/O
  thread; `nl_send()` and `nl_poll_event()` can be called from any thread
  without external locking.
- **IPv6 support**, dual-stack where the OS allows it (implemented and
  exercised in code review; see [Testing](#testing) for why it couldn't
  be run to completion in this project's own dev sandbox).
- **LAN server discovery** via UDP broadcast (probe/reply with server
  name and player count) -- handy for local multiplayer without a
  master server.
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

### Deliberately not included (see [Roadmap](#roadmap--known-limitations))

- **WebRTC.** A correct, secure WebRTC implementation (ICE + DTLS + SCTP)
  is a large undertaking in its own right, and a half-correct one is a
  security liability. Not included; see the roadmap.
- **WebSocket transport.** `NL_TRANSPORT_WEBSOCKET` is defined in the
  public API as a placeholder for browser interop but is not implemented
  yet (`nl_server_create`/`nl_client_create` return `NL_ERR_UNSUPPORTED`
  for it today).

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
    if (ev.type == NL_EVENT_DATA) {
        nl_send(server, ev.peer, ev.channel, NL_RELIABLE_ORDERED, ev.data, ev.data_len); // echo
    }
}
```

See `examples/echo_server.c` and `examples/echo_client.c` for complete,
runnable programs.

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

See `bindings/go/README.md` and `bindings/rust/README.md` -- note the
testing-status caveat in each (summarized in [Testing](#testing) below).

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
environment** (a sandboxed Linux container with a C toolchain, OpenSSL,
and Python, but no Go/Rust toolchain, no IPv6 support at the kernel
level, and no network access to install either):

- 112 test cases across unit tests (`tests/test_seqbuf.c`,
  `test_crypto.c`, `test_fragment.c`, `test_channel.c`,
  `test_connection.c`, `test_network_simulation.c`) and real-socket
  integration tests (`tests/integration/test_integration.c`), all clean
  under AddressSanitizer + UndefinedBehaviorSanitizer -- no leaks, no UB.
- `test_network_simulation.c` specifically drives thousands of messages
  through a simulated bad network (configurable packet loss, jitter/
  reordering, duplication) and verifies `RELIABLE_ORDERED` delivery stays
  complete and correctly ordered throughout -- including at 20% loss and
  25% duplication -- rather than only ever being exercised over perfect
  localhost conditions.
- The integration tests spin up **real client and server endpoints
  communicating over actual loopback UDP sockets**, covering: the full
  encrypted handshake, all four delivery modes, fragmentation of a
  5000-byte message, multiple independent channels, graceful disconnect,
  LAN discovery, and server-full denial.
- The **Python bindings**, tested the same way (real `Server` + `Client`
  over real sockets, plus a manual run against the compiled C example
  binaries as separate OS processes) -- 5/5 passing.
- The **example C programs** (`echo_server`/`echo_client`), run as two
  independent OS processes exchanging messages across three channels and
  delivery modes.

**Written but not compiled/run here, for lack of toolchain:**

- The **Go bindings** (`bindings/go`) and **Rust bindings**
  (`bindings/rust`). Both are written carefully against the exact struct
  layouts in `include/netlink.h` (the same header the Python bindings
  were verified against), following standard cgo/FFI patterns, but they
  need a first real `go build`/`cargo build` pass. Each binding's README
  says this explicitly.
- **Windows** (`socket_compat.h`'s `_WIN32` branch uses documented Winsock
  APIs following the same logic as the POSIX path, but wasn't build-tested
  here).
- **IPv6**, at the integration-test level: the code path is implemented
  (dual-stack binding, `AF_INET6` throughout) and the test for it exists
  and runs, but this sandbox's container has no IPv6 support at the
  kernel/namespace level at all (`socket(AF_INET6, ...)` itself fails),
  so the test skips itself rather than reporting a false pass. If you run
  the test suite somewhere with IPv6 available, please check that it
  actually passes.

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
- **WebSocket transport and WebRTC** are not implemented (see Features).
- **Connection table lookup is O(n)** (linear scan, bounded at 512
  connections internally). Fine for small-to-medium deployments; a hash
  map would be a straightforward improvement for large ones.

### Future work

An external review of this project suggested a substantial list of
additions to move NetLink from "capable UDP library" toward something
closer to a full modern transport (congestion control, connection
migration, flow control, priority/QoS, an RPC layer, built-in
serialization, compression, protocol capability negotiation, and more --
plus infrastructure like CMake, fuzzing, and multi-OS CI). It's good
feedback and most of it is a genuine gap, not a nitpick. Implementing all
of it to the same tested standard as the rest of this project is
realistically a much larger effort than one pass; RTT-based adaptive
retransmission, fast retransmit, per-peer stats, and a randomized
network-condition test harness (see Testing above) have been implemented
and tested as a first slice. Roughly in priority order for what's left:

1. **Congestion control** -- RTT/loss-based send-rate adaptation
   (something closer to slow-start + congestion avoidance than the
   current fixed-window reliable sending), important once multiple
   clients share a server's bandwidth.
2. **Connection migration** -- `PATH_CHALLENGE`/`PATH_RESPONSE` so a
   client changing networks (mobile Wi-Fi <-> cellular, NAT rebind)
   doesn't need a full reconnect, QUIC-style.
3. **Flow control** -- a receive window bounding how much a fast sender
   can have outstanding against a slow receiver, distinct from congestion
   control (which asks what the *network* can handle; flow control asks
   what the *receiver* can handle).
4. **Expanded/range-based ACKs** -- the current 32-bit ack bitmap works
   well for the loss patterns tested above, but wider bitmaps or explicit
   ranges would help on very high-latency/lossy links.
5. **Priority/QoS per send**, **per-connection rate limiting**, **an
   optional RPC layer with request/response semantics**, **built-in
   (optional, separate-from-core) serialization**, **compression**
   (compress-then-encrypt, never the reverse), **protocol capability
   negotiation during the handshake** (so future versions don't require
   moving in lockstep), and the **WebSocket transport** already reserved
   in the API.
6. Smaller infrastructure: a C++ RAII wrapper, CMake alongside the
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

### Unreleased

Code review pass over the 0.1.0 core; all findings fixed with regression
tests (`make` warning-free, `make test` green under ASan/UBSan). Wire
format and `NL_PROTOCOL_VERSION` unchanged.

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
  nonce (delayed/forged replies are dropped). Discovery has its own
  rate-limit budget (200/s/endpoint), separate from the handshake
  limiter, so a flood of probes can't starve connect attempts.
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
- **Regression tests** for the above: sequenced out-of-order fragments,
  channel-tick reassembly expiry, ACCEPTED retransmit budget,
  `encryption_enabled` rejection, duplicate connect, discovery wrong
  nonce + rate limit (raw-socket injection, works without broadcast),
  `max_connections` clamp, and `server_name` copy.
