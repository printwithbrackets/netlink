/*
 * weft_net.h - Public API for weft-net
 *
 * A lightweight, secure, UDP-based network communication library for games
 * and general-purpose client/server applications.
 *
 * This header is the stable C ABI. All language bindings (Python, Go, Rust,
 * C++) are built against exactly this interface, so every language talks
 * the same wire protocol through the same battle-tested core.
 *
 * Thread-safety: every function documented "thread-safe" may be called
 * concurrently from any thread without external locking. wn_endpoint_t
 * internally runs its own I/O thread(s); you drive it from your own
 * thread(s) via wn_poll_event() (typically your game loop).
 *
 * License: MIT (see LICENSE)
 */
#ifndef WEFT_NET_H
#define WEFT_NET_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI guard for the structs the language bindings mirror by hand.
 *
 * The Python and Rust bindings declare their own copies of these layouts
 * (ctypes.Structure / #[repr(C)]) rather than including this header, so a
 * field added on the C side and forgotten on the binding side compiles
 * cleanly in BOTH languages and then corrupts memory at runtime:
 * wn_config_default() writes past the end of the binding's shorter struct.
 * That exact mismatch shipped in 1.0.0 (three fields missing from both
 * mirrors). These asserts pin the sizes so the C side at least fails to
 * build when a struct changes, and the bindings' tests assert the same
 * numbers against the real library.
 *
 * Sizes are asserted for the 64-bit ABI only; a 32-bit build legitimately
 * differs (pointers are 4 bytes and the structs contain pointers), and the
 * bindings are written against this ABI. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(WN_SKIP_ABI_ASSERTS)
  #if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFULL
    #define WN_ABI_ASSERT(cond, msg) _Static_assert(cond, msg)
  #else
    #define WN_ABI_ASSERT(cond, msg) ((void)0)
  #endif
#else
  /* Pre-C11 (or C++ without _Static_assert): no compile-time guard. The
   * binding tests still check the sizes at runtime. */
  #define WN_ABI_ASSERT(cond, msg) ((void)0)
#endif

#if defined(_WIN32) && defined(WEFT_NET_SHARED)
  #ifdef WEFT_NET_BUILD
    #define WN_API __declspec(dllexport)
  #else
    #define WN_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) || defined(__clang__)
  #define WN_API __attribute__((visibility("default")))
#else
  #define WN_API /* e.g. MSVC building the static library: no attribute to apply */
#endif

/* ----------------------------------------------------------------------- */
/* Version                                                                  */
/* ----------------------------------------------------------------------- */

#define WN_VERSION_MAJOR 1
#define WN_VERSION_MINOR 3
#define WN_VERSION_PATCH 0

/* Wire protocol version. Bumped whenever the on-the-wire packet format
 * changes in an incompatible way. Peers with different values refuse to
 * connect to each other rather than risk misinterpreting bytes.
 *
 * v2: DATA cleartext headers carry a u16 receive window (flow control);
 * CONNECT_REQUEST / CONNECT_CHALLENGE carry a u32 capability bitmask
 * (negotiated as the bitwise AND of both peers' advertised sets).
 * v3: new encrypted WN_PKT_ACK packet (reliable receivers send standalone
 * acks when no reverse DATA exists to piggyback them on); discovery probe
 * nonces are random rather than a counter.
 * v4: the DATA header gains a u8 ack_valid, so "no ack yet" is no longer
 * indistinguishable from "I have sequence 0" (header and ACK payload each
 * grow by one byte).
 * v5: ack_bits widens from u32 to u64 (WN_ACK_WINDOW_BITS = 64). */
#define WN_PROTOCOL_VERSION 5

/* ----------------------------------------------------------------------- */
/* Capabilities (exchanged during the handshake; negotiated = AND of both)  */
/* ----------------------------------------------------------------------- */

/* Bit 0: peer includes a u16 receive window in every DATA header and will
 * defer sends when the advertised window is full. Implied by protocol v2
 * (the field is always present); the bit is still advertised so future
 * optional features can use the same mechanism without another version bump. */
#define WN_CAP_FLOW_CONTROL  0x00000001u
/* Bit 1: peer understands priority-tagged sends (reserved for when
 * priority is reflected on the wire rather than only in the local queue). */
#define WN_CAP_PRIORITY      0x00000002u
/* Bit 2: peer applies a sender-side rate limit when configured (reserved
 * for cross-implementation signalling; enforcement is always local). */
#define WN_CAP_RATE_LIMIT    0x00000004u
/* Default advertised set. WN_CAP_FLOW_CONTROL is always forced on. */
#define WN_CAP_DEFAULT (WN_CAP_FLOW_CONTROL | WN_CAP_PRIORITY | WN_CAP_RATE_LIMIT)

/* ----------------------------------------------------------------------- */
/* Send priorities (wn_send_ex; wn_send uses WN_PRIORITY_NORMAL)           */
/* ----------------------------------------------------------------------- */

#define WN_PRIORITY_LOW        0
#define WN_PRIORITY_NORMAL     64
#define WN_PRIORITY_HIGH       128
#define WN_PRIORITY_CRITICAL   192

WN_API const char *wn_version_string(void);

/* ----------------------------------------------------------------------- */
/* Limits (also enforced internally -- exposed so callers can size buffers) */
/* ----------------------------------------------------------------------- */

#define WN_MAX_CHANNELS            32
#define WN_MAX_PACKET_SIZE         1200   /* single UDP datagram payload, safe under typical MTUs */
#define WN_MAX_MESSAGE_SIZE        (256 * 1024) /* after reassembly */
#define WN_MAX_FRAGMENTS           256
#define WN_CONNECT_TOKEN_SIZE      16
#define WN_PUBLIC_KEY_SIZE         32
#define WN_SERVER_NAME_MAX         64

/* ----------------------------------------------------------------------- */
/* Error codes                                                             */
/* ----------------------------------------------------------------------- */

typedef enum {
    WN_OK                       = 0,
    WN_ERR_INVALID_ARGUMENT     = -1,
    WN_ERR_OUT_OF_MEMORY        = -2,
    WN_ERR_SOCKET               = -3,
    WN_ERR_BIND_FAILED          = -4,
    WN_ERR_NOT_CONNECTED        = -5,
    WN_ERR_ALREADY_CONNECTED    = -6,
    WN_ERR_MESSAGE_TOO_LARGE    = -7,
    WN_ERR_CHANNEL_OUT_OF_RANGE = -8,
    WN_ERR_QUEUE_FULL           = -9,
    WN_ERR_CRYPTO               = -10,
    WN_ERR_PROTOCOL_MISMATCH    = -11,
    WN_ERR_TIMEOUT              = -12,
    WN_ERR_PEER_NOT_FOUND       = -13,
    WN_ERR_DENIED               = -14,
    WN_ERR_UNSUPPORTED          = -15,
    WN_ERR_SERVER_FULL          = -16,
    WN_ERR_INTERNAL             = -99,
} wn_result_t;

WN_API const char *wn_error_string(wn_result_t code);

/* ----------------------------------------------------------------------- */
/* Delivery / reliability modes                                            */
/* ----------------------------------------------------------------------- */

typedef enum {
    /* Fire and forget. May be lost, duplicated, or reordered. Cheapest. */
    WN_UNRELIABLE = 0,
    /* Not retransmitted, but stale/out-of-order packets are dropped on
     * arrival so the application only ever sees newer data (great for
     * position updates where only the latest value matters). */
    WN_UNRELIABLE_SEQUENCED = 1,
    /* Guaranteed to arrive (retransmitted until acked), but may be
     * delivered to the application out of order. */
    WN_RELIABLE_UNORDERED = 2,
    /* Guaranteed to arrive AND guaranteed to be delivered to the
     * application in the exact order it was sent. */
    WN_RELIABLE_ORDERED = 3,
} wn_delivery_t;

/* ----------------------------------------------------------------------- */
/* Address family                                                          */
/* ----------------------------------------------------------------------- */

typedef enum {
    WN_AF_UNSPEC = 0, /* unspecified: getaddrinfo picks (IPv4 for the
                        * default client socket, either family for bind) */
    WN_AF_INET   = 4,
    WN_AF_INET6  = 6,
} wn_af_t;

typedef struct {
    char     host[64];  /* numeric or presentation address, e.g. "::1", "192.168.1.5" */
    uint16_t port;
    wn_af_t  family;
} wn_address_t;

WN_ABI_ASSERT(sizeof(wn_address_t) == 72,
              "wn_address_t changed size -- update the Python/Rust mirrors "
              "and their size assertions (the host buffer size is ABI)");

/* ----------------------------------------------------------------------- */
/* Opaque handles                                                          */
/* ----------------------------------------------------------------------- */

typedef struct wn_endpoint wn_endpoint_t;
typedef uint64_t wn_peer_id_t;
#define WN_INVALID_PEER 0

/* ----------------------------------------------------------------------- */
/* Transport                                                               */
/* ----------------------------------------------------------------------- */

typedef enum {
    WN_TRANSPORT_UDP       = 0, /* native UDP, lowest latency, recommended for native clients */
    WN_TRANSPORT_WEBSOCKET = 1, /* TCP + RFC6455 WebSocket framing, for browser interop */
} wn_transport_t;

/* ----------------------------------------------------------------------- */
/* Channel configuration                                                   */
/* ----------------------------------------------------------------------- */

typedef struct {
    uint8_t channel_count;   /* number of independent channels, 1..WN_MAX_CHANNELS */
} wn_channel_config_t;

/* ----------------------------------------------------------------------- */
/* Endpoint configuration                                                  */
/* ----------------------------------------------------------------------- */

typedef struct {
    wn_transport_t transport;
    wn_af_t        family;              /* address family to bind/connect with */
    uint8_t        channel_count;       /* 1..WN_MAX_CHANNELS, default 4 */
    uint32_t       max_connections;     /* server only; 0 = library default (64), capped at 512 */
    uint32_t       connection_timeout_ms; /* no traffic for this long => disconnect; 0 = default (10000) */
    uint32_t       keepalive_interval_ms; /* 0 = default (1000) */
    bool           encryption_enabled;  /* must be true (the default). false returns WN_ERR_UNSUPPORTED
                                           from wn_server_create/wn_client_create -- there is no cleartext mode. */
    const char    *server_name;         /* used in discovery responses, optional; copied by the library */
    /* Per-connection sender rate limit, payload bytes/second (0 = unlimited).
     * Applies to newly emitted DATA only; retransmits and keepalives are
     * exempt so recovery traffic is never starved by the limiter. */
    uint32_t       max_send_bytes_per_sec;
    /* Receive window advertised to peers (bytes of unconsumed DATA events
     * the endpoint will buffer before telling them to stop). 0 = default
     * (32768), clamped to 65535 to fit the u16 wire field. */
    uint32_t       recv_window_bytes;
    /* Global byte cap on event payload bytes queued endpoint-wide across
     * all connections (sum of the payload lengths of events not yet
     * consumed with wn_poll_event). When a new event would push the total
     * above the cap, that event is REJECTED (not queued) and the sender
     * keeps its receive-window charge for it, so its flow-control window
     * stays closed first. This caps the memory one hostile peer -- or a
     * burst across all peers -- can pin in the queue; draining with
     * wn_poll_event opens room again. Queued events already accepted are
     * never dropped by this limit.
     *
     * 0 = library default (WN_EVENT_QUEUE_MAX_BYTES_DEFAULT, sized at
     * roughly the default configuration's peak: 64 connections x the
     * 32768-byte default receive window, rounded up). WN_EVENT_QUEUE_
     * UNLIMITED restores the effectively unbounded queue of 1.1.x
     * explicitly. Note events other than WN_EVENT_DATA carry a zero
     * payload length and fit freely, but under a full queue they are
     * rejected like any other event until the queue drains below the cap. */
    uint32_t       event_queue_max_bytes;
    /* Capability bits advertised in the handshake (0 = WN_CAP_DEFAULT).
     * WN_CAP_FLOW_CONTROL is always forced on. */
    uint32_t       capabilities;
} wn_config_t;

/* Sane default for wn_config_t.event_queue_max_bytes (0 means "this"
 * value): ~2x the default configuration's peak queued bytes
 * (64 connections x the 32768-byte default receive window), leaving
 * headroom for per-thread payload borrows, which are charged to the
 * connection but never sit in the queue itself. Raise it alongside
 * max_connections/recv_window_bytes in configs that use bigger values. */
#define WN_EVENT_QUEUE_MAX_BYTES_DEFAULT (4u * 1024u * 1024u)
/* Set wn_config_t.event_queue_max_bytes to this to restore the 1.1.x
 * effectively unbounded event queue explicitly. */
#define WN_EVENT_QUEUE_UNLIMITED 0xFFFFFFFFu

/* 64 bytes would be the pre-v2 size; 56 is with all three v2 fields AND
 * event_queue_max_bytes (a trailing-alignment pad slot absorbs the v2
 * extension, so the 64-bit size was already 56 -- the mirror-side asserts
 * below are what actually catches a forgotten field on either side). */
WN_ABI_ASSERT(sizeof(wn_config_t) == 56,
              "wn_config_t changed size -- update the Python/Rust mirrors "
              "and their size assertions (they mirror this struct by hand)");

WN_API void wn_config_default(wn_config_t *cfg);

/* ----------------------------------------------------------------------- */
/* Events                                                                   */
/* ----------------------------------------------------------------------- */

typedef enum {
    WN_EVENT_NONE           = 0,
    /* Fired once the handshake is confirmed for this endpoint: on the
     * server when CONNECT_RESPONSE completes (before the client has
     * necessarily seen CONNECT_ACCEPTED), on the client when
     * CONNECT_ACCEPTED decrypts. The two sides can therefore observe
     * CONNECTED at slightly different instants; treat it as "this peer
     * exists and keys are live", not a barrier both sides hit together. */
    WN_EVENT_CONNECTED      = 1, /* peer field valid */
    WN_EVENT_DISCONNECTED   = 2, /* peer field valid, disconnect_reason valid */
    WN_EVENT_DATA           = 3, /* peer, channel, data, data_len valid */
    WN_EVENT_CONNECT_FAILED = 4, /* client only; disconnect_reason valid */
    WN_EVENT_DISCOVERY_REPLY= 5, /* discovery fields valid */
} wn_event_type_t;

typedef struct {
    wn_event_type_t event_type; /* named event_type, not type, to avoid colliding
                                    with the "type"/"type_" reserved keyword in
                                    several language bindings (Go, Rust, etc.) */
    wn_peer_id_t    peer;
    uint8_t         channel;
    const uint8_t  *data;      /* borrowed pointer, valid until next poll call */
    size_t          data_len;
    wn_result_t     disconnect_reason;
    wn_address_t    from_address;      /* DISCOVERY_REPLY / CONNECTED */
    char            server_name[WN_SERVER_NAME_MAX];
    uint32_t        server_player_count;
    uint32_t        server_max_players;
} wn_event_t;

WN_ABI_ASSERT(sizeof(wn_event_t) == 192,
              "wn_event_t changed size -- update the Python/Rust mirrors "
              "and their size assertions");

/* ----------------------------------------------------------------------- */
/* Lifecycle                                                                */
/* ----------------------------------------------------------------------- */

/* Create a server endpoint bound to bind_addr and start accepting connections.
 * Spawns background I/O threads. Thread-safe to call from any thread. */
WN_API wn_result_t wn_server_create(const wn_address_t *bind_addr,
                                     const wn_config_t *cfg,
                                     wn_endpoint_t **out_endpoint);

/* Create a client endpoint (not yet connected to anything). */
WN_API wn_result_t wn_client_create(const wn_config_t *cfg,
                                     wn_endpoint_t **out_endpoint);

/* Begin connecting to a remote server. Non-blocking; results in an
 * WN_EVENT_CONNECTED or WN_EVENT_CONNECT_FAILED event. Returns
 * WN_ERR_ALREADY_CONNECTED if a handshake to this address is already in
 * flight or a connection to it already exists. An empty server_addr.host
 * is WN_ERR_INVALID_ARGUMENT (it never defaults to 127.0.0.1). */
WN_API wn_result_t wn_connect(wn_endpoint_t *ep, const wn_address_t *server_addr,
                               wn_peer_id_t *out_peer);

/* Gracefully close a connection (sends a disconnect notification, best-effort). */
WN_API wn_result_t wn_disconnect(wn_endpoint_t *ep, wn_peer_id_t peer);

/* Shut down the endpoint, stop threads, free all resources.
 * Any peer handles from this endpoint become invalid.
 *
 * Contract: no other thread may be inside any wn_* call on `ep` when
 * destroy is invoked, with one exception: threads already blocked in
 * wn_poll_event at that moment (any timeout, including -1) are woken and
 * return false safely, so they never touch ep memory after destroy frees
 * it. A poll that is mid-return when destroy starts also completes its
 * final bookkeeping before destroy's wait-for-pollers finishes, so queued
 * payloads and the queue itself cannot be freed under an exiting poller. */
WN_API void wn_endpoint_destroy(wn_endpoint_t *ep);

/* ----------------------------------------------------------------------- */
/* I/O                                                                      */
/* ----------------------------------------------------------------------- */

/* Enqueue `len` bytes for delivery to `peer` on `channel` using `delivery`.
 * Thread-safe: may be called concurrently from multiple threads, including
 * concurrently with wn_poll_event(). Copies `data` internally; the caller's
 * buffer may be reused/freed immediately after this returns.
 * `data` may be NULL when len is 0 (a valid, deliverable empty message).
 *
 * Equivalent to wn_send_ex(..., WN_PRIORITY_NORMAL). The send may be
 * deferred internally (congestion window, peer receive window, or rate
 * limit) and still return WN_OK -- WN_ERR_QUEUE_FULL is only returned
 * when the per-connection deferred queue itself is full. The deferred
 * queue is bounded per connection to 128 messages AND
 * WN_MAX_MESSAGE_SIZE + 64KB of payload bytes (both bound the memory a
 * sender's own application can allocate against a stalled peer). */
WN_API wn_result_t wn_send(wn_endpoint_t *ep, wn_peer_id_t peer, uint8_t channel,
                            wn_delivery_t delivery, const uint8_t *data, size_t len);

/* Like wn_send, with an explicit priority (0..255, higher = more urgent).
 * When the connection's send window is closed, messages are queued and
 * flushed highest-priority-first as window/rate budget opens. */
WN_API wn_result_t wn_send_ex(wn_endpoint_t *ep, wn_peer_id_t peer, uint8_t channel,
                              wn_delivery_t delivery, const uint8_t *data, size_t len,
                              uint8_t priority);

/* Pop the next event, waiting up to timeout_ms for one to arrive (0 = don't
 * block, -1 = block forever). Returns true if an event was written to *out.
 *
 * Thread-safe: callable from any thread, and concurrently from several. The
 * returned `out->data` (for WN_EVENT_DATA) is owned by the library and
 * borrowed to the CALLING THREAD: it stays valid until that same thread's
 * next call to wn_poll_event, or until the endpoint is destroyed. Other
 * threads polling in the meantime never free it. Copy the bytes if you need
 * them longer.
 *
 * If wn_endpoint_destroy is called while this call is blocked (any timeout,
 * including -1), it wakes the blocked poller and the call returns false;
 * see the destroy contract on wn_endpoint_destroy. */
WN_API bool wn_poll_event(wn_endpoint_t *ep, wn_event_t *out, int timeout_ms);

/* ----------------------------------------------------------------------- */
/* Discovery / lobby                                                       */
/* ----------------------------------------------------------------------- */

/* Server: start responding to LAN discovery broadcasts on discovery_port. */
WN_API wn_result_t wn_discovery_enable(wn_endpoint_t *ep, uint16_t discovery_port);

/* Client: broadcast a discovery probe on the LAN and collect replies as
 * WN_EVENT_DISCOVERY_REPLY events over the next ~timeout_ms. */
WN_API wn_result_t wn_discovery_probe(wn_endpoint_t *ep, uint16_t discovery_port, int timeout_ms);

/* ----------------------------------------------------------------------- */
/* Introspection                                                           */
/* ----------------------------------------------------------------------- */

WN_API bool wn_peer_address(wn_endpoint_t *ep, wn_peer_id_t peer, wn_address_t *out);
WN_API uint32_t wn_peer_rtt_ms(wn_endpoint_t *ep, wn_peer_id_t peer);
WN_API uint32_t wn_peer_count(wn_endpoint_t *ep);

/* Per-peer counters and timing estimates: sent/received packet and byte
 * counts, retransmissions (RTO-triggered and fast-retransmit combined),
 * duplicate/replayed packets rejected, and RTT statistics (smoothed RTT,
 * smoothed RTT variance, and the currently-derived retransmit timeout --
 * see the README's Features section for the estimation algorithm).
 * Useful for in-game network diagnostics ("Ping: 42ms, Loss: 0.7%") or
 * server-side monitoring. */
typedef struct {
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t retransmits;
    uint64_t duplicates_received;
    uint32_t rtt_ms;
    uint32_t rtt_var_ms;
    uint32_t rto_ms;
} wn_peer_stats_t;

WN_ABI_ASSERT(sizeof(wn_peer_stats_t) == 64,
              "wn_peer_stats_t changed size -- update the Python/Rust mirrors "
              "and their size assertions");

/* Copy out a snapshot of `peer`'s counters and RTT estimates. Returns
 * false if `peer` is not a currently-known connection. Thread-safe. */
WN_API bool wn_peer_stats(wn_endpoint_t *ep, wn_peer_id_t peer, wn_peer_stats_t *out);

/* Copy out the capability bits negotiated with `peer` during the
 * handshake (bitwise AND of both peers' advertised sets). Returns false
 * if `peer` is not a currently-known connection. Thread-safe. */
WN_API bool wn_peer_capabilities(wn_endpoint_t *ep, wn_peer_id_t peer, uint32_t *out_caps);

#ifdef __cplusplus
}
#endif

#endif /* WEFT_NET_H */
