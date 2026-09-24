/*
 * netlink.h - Public API for NetLink
 *
 * A lightweight, secure, UDP-based network communication library for games
 * and general-purpose client/server applications.
 *
 * This header is the stable C ABI. All language bindings (Python, Go, Rust,
 * C++) are built against exactly this interface, so every language talks
 * the same wire protocol through the same battle-tested core.
 *
 * Thread-safety: every function documented "thread-safe" may be called
 * concurrently from any thread without external locking. nl_endpoint_t
 * internally runs its own I/O thread(s); you drive it from your own
 * thread(s) via nl_poll_event() (typically your game loop).
 *
 * License: MIT (see LICENSE)
 */
#ifndef NETLINK_H
#define NETLINK_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(NETLINK_SHARED)
  #ifdef NETLINK_BUILD
    #define NL_API __declspec(dllexport)
  #else
    #define NL_API __declspec(dllimport)
  #endif
#else
  #define NL_API __attribute__((visibility("default")))
#endif

/* ----------------------------------------------------------------------- */
/* Version                                                                  */
/* ----------------------------------------------------------------------- */

#define NL_VERSION_MAJOR 0
#define NL_VERSION_MINOR 1
#define NL_VERSION_PATCH 0

/* Wire protocol version. Bumped whenever the on-the-wire packet format
 * changes in an incompatible way. Peers with different values refuse to
 * connect to each other rather than risk misinterpreting bytes.
 *
 * v2: DATA cleartext headers carry a u16 receive window (flow control);
 * CONNECT_REQUEST / CONNECT_CHALLENGE carry a u32 capability bitmask
 * (negotiated as the bitwise AND of both peers' advertised sets). */
#define NL_PROTOCOL_VERSION 2

/* ----------------------------------------------------------------------- */
/* Capabilities (exchanged during the handshake; negotiated = AND of both)  */
/* ----------------------------------------------------------------------- */

/* Bit 0: peer includes a u16 receive window in every DATA header and will
 * defer sends when the advertised window is full. Implied by protocol v2
 * (the field is always present); the bit is still advertised so future
 * optional features can use the same mechanism without another version bump. */
#define NL_CAP_FLOW_CONTROL  0x00000001u
/* Bit 1: peer understands priority-tagged sends (reserved for when
 * priority is reflected on the wire rather than only in the local queue). */
#define NL_CAP_PRIORITY      0x00000002u
/* Bit 2: peer applies a sender-side rate limit when configured (reserved
 * for cross-implementation signalling; enforcement is always local). */
#define NL_CAP_RATE_LIMIT    0x00000004u
/* Default advertised set. NL_CAP_FLOW_CONTROL is always forced on for v2. */
#define NL_CAP_DEFAULT (NL_CAP_FLOW_CONTROL | NL_CAP_PRIORITY | NL_CAP_RATE_LIMIT)

/* ----------------------------------------------------------------------- */
/* Send priorities (nl_send_ex; nl_send uses NL_PRIORITY_NORMAL)           */
/* ----------------------------------------------------------------------- */

#define NL_PRIORITY_LOW        0
#define NL_PRIORITY_NORMAL     64
#define NL_PRIORITY_HIGH       128
#define NL_PRIORITY_CRITICAL   192

NL_API const char *nl_version_string(void);

/* ----------------------------------------------------------------------- */
/* Limits (also enforced internally -- exposed so callers can size buffers) */
/* ----------------------------------------------------------------------- */

#define NL_MAX_CHANNELS            32
#define NL_MAX_PACKET_SIZE         1200   /* single UDP datagram payload, safe under typical MTUs */
#define NL_MAX_MESSAGE_SIZE        (256 * 1024) /* after reassembly */
#define NL_MAX_FRAGMENTS           256
#define NL_CONNECT_TOKEN_SIZE      16
#define NL_PUBLIC_KEY_SIZE         32
#define NL_SERVER_NAME_MAX         64

/* ----------------------------------------------------------------------- */
/* Error codes                                                             */
/* ----------------------------------------------------------------------- */

typedef enum {
    NL_OK                       = 0,
    NL_ERR_INVALID_ARGUMENT     = -1,
    NL_ERR_OUT_OF_MEMORY        = -2,
    NL_ERR_SOCKET               = -3,
    NL_ERR_BIND_FAILED          = -4,
    NL_ERR_NOT_CONNECTED        = -5,
    NL_ERR_ALREADY_CONNECTED    = -6,
    NL_ERR_MESSAGE_TOO_LARGE    = -7,
    NL_ERR_CHANNEL_OUT_OF_RANGE = -8,
    NL_ERR_QUEUE_FULL           = -9,
    NL_ERR_CRYPTO               = -10,
    NL_ERR_PROTOCOL_MISMATCH    = -11,
    NL_ERR_TIMEOUT              = -12,
    NL_ERR_PEER_NOT_FOUND       = -13,
    NL_ERR_DENIED               = -14,
    NL_ERR_UNSUPPORTED          = -15,
    NL_ERR_SERVER_FULL          = -16,
    NL_ERR_INTERNAL             = -99,
} nl_result_t;

NL_API const char *nl_error_string(nl_result_t code);

/* ----------------------------------------------------------------------- */
/* Delivery / reliability modes                                            */
/* ----------------------------------------------------------------------- */

typedef enum {
    /* Fire and forget. May be lost, duplicated, or reordered. Cheapest. */
    NL_UNRELIABLE = 0,
    /* Not retransmitted, but stale/out-of-order packets are dropped on
     * arrival so the application only ever sees newer data (great for
     * position updates where only the latest value matters). */
    NL_UNRELIABLE_SEQUENCED = 1,
    /* Guaranteed to arrive (retransmitted until acked), but may be
     * delivered to the application out of order. */
    NL_RELIABLE_UNORDERED = 2,
    /* Guaranteed to arrive AND guaranteed to be delivered to the
     * application in the exact order it was sent. */
    NL_RELIABLE_ORDERED = 3,
} nl_delivery_t;

/* ----------------------------------------------------------------------- */
/* Address family                                                          */
/* ----------------------------------------------------------------------- */

typedef enum {
    NL_AF_UNSPEC = 0, /* resolve automatically (prefers IPv6 if available) */
    NL_AF_INET   = 4,
    NL_AF_INET6  = 6,
} nl_af_t;

typedef struct {
    char     host[64];  /* numeric or presentation address, e.g. "::1", "192.168.1.5" */
    uint16_t port;
    nl_af_t  family;
} nl_address_t;

/* ----------------------------------------------------------------------- */
/* Opaque handles                                                          */
/* ----------------------------------------------------------------------- */

typedef struct nl_endpoint nl_endpoint_t;
typedef uint64_t nl_peer_id_t;
#define NL_INVALID_PEER 0

/* ----------------------------------------------------------------------- */
/* Transport                                                               */
/* ----------------------------------------------------------------------- */

typedef enum {
    NL_TRANSPORT_UDP       = 0, /* native UDP, lowest latency, recommended for native clients */
    NL_TRANSPORT_WEBSOCKET = 1, /* TCP + RFC6455 WebSocket framing, for browser interop */
} nl_transport_t;

/* ----------------------------------------------------------------------- */
/* Channel configuration                                                   */
/* ----------------------------------------------------------------------- */

typedef struct {
    uint8_t channel_count;   /* number of independent channels, 1..NL_MAX_CHANNELS */
} nl_channel_config_t;

/* ----------------------------------------------------------------------- */
/* Endpoint configuration                                                  */
/* ----------------------------------------------------------------------- */

typedef struct {
    nl_transport_t transport;
    nl_af_t        family;              /* address family to bind/connect with */
    uint8_t        channel_count;       /* 1..NL_MAX_CHANNELS, default 4 */
    uint32_t       max_connections;     /* server only; 0 = library default (64), capped at 512 */
    uint32_t       connection_timeout_ms; /* no traffic for this long => disconnect; 0 = default (10000) */
    uint32_t       keepalive_interval_ms; /* 0 = default (1000) */
    bool           encryption_enabled;  /* must be true (the default). false returns NL_ERR_UNSUPPORTED
                                           from nl_server_create/nl_client_create -- there is no cleartext mode. */
    const char    *server_name;         /* used in discovery responses, optional; copied by the library */
    /* Per-connection sender rate limit, payload bytes/second (0 = unlimited).
     * Applies to newly emitted DATA only; retransmits and keepalives are
     * exempt so recovery traffic is never starved by the limiter. */
    uint32_t       max_send_bytes_per_sec;
    /* Receive window advertised to peers (bytes of unconsumed DATA events
     * the endpoint will buffer before telling them to stop). 0 = default
     * (32768), clamped to 65535 to fit the u16 wire field. */
    uint32_t       recv_window_bytes;
    /* Capability bits advertised in the handshake (0 = NL_CAP_DEFAULT).
     * NL_CAP_FLOW_CONTROL is always forced on under protocol v2. */
    uint32_t       capabilities;
} nl_config_t;

NL_API void nl_config_default(nl_config_t *cfg);

/* ----------------------------------------------------------------------- */
/* Events                                                                   */
/* ----------------------------------------------------------------------- */

typedef enum {
    NL_EVENT_NONE           = 0,
    NL_EVENT_CONNECTED      = 1, /* peer field valid */
    NL_EVENT_DISCONNECTED   = 2, /* peer field valid, disconnect_reason valid */
    NL_EVENT_DATA           = 3, /* peer, channel, data, data_len valid */
    NL_EVENT_CONNECT_FAILED = 4, /* client only; disconnect_reason valid */
    NL_EVENT_DISCOVERY_REPLY= 5, /* discovery fields valid */
} nl_event_type_t;

typedef struct {
    nl_event_type_t event_type; /* named event_type, not type, to avoid colliding
                                    with the "type"/"type_" reserved keyword in
                                    several language bindings (Go, Rust, etc.) */
    nl_peer_id_t    peer;
    uint8_t         channel;
    const uint8_t  *data;      /* borrowed pointer, valid until next poll call */
    size_t          data_len;
    nl_result_t     disconnect_reason;
    nl_address_t    from_address;      /* DISCOVERY_REPLY / CONNECTED */
    char            server_name[NL_SERVER_NAME_MAX];
    uint32_t        server_player_count;
    uint32_t        server_max_players;
} nl_event_t;

/* ----------------------------------------------------------------------- */
/* Lifecycle                                                                */
/* ----------------------------------------------------------------------- */

/* Create a server endpoint bound to bind_addr and start accepting connections.
 * Spawns background I/O threads. Thread-safe to call from any thread. */
NL_API nl_result_t nl_server_create(const nl_address_t *bind_addr,
                                     const nl_config_t *cfg,
                                     nl_endpoint_t **out_endpoint);

/* Create a client endpoint (not yet connected to anything). */
NL_API nl_result_t nl_client_create(const nl_config_t *cfg,
                                     nl_endpoint_t **out_endpoint);

/* Begin connecting to a remote server. Non-blocking; results in an
 * NL_EVENT_CONNECTED or NL_EVENT_CONNECT_FAILED event. Returns
 * NL_ERR_ALREADY_CONNECTED if a handshake to this address is already in
 * flight or a connection to it already exists. */
NL_API nl_result_t nl_connect(nl_endpoint_t *ep, const nl_address_t *server_addr,
                               nl_peer_id_t *out_peer);

/* Gracefully close a connection (sends a disconnect notification, best-effort). */
NL_API nl_result_t nl_disconnect(nl_endpoint_t *ep, nl_peer_id_t peer);

/* Shut down the endpoint, stop threads, free all resources.
 * Any peer handles from this endpoint become invalid. */
NL_API void nl_endpoint_destroy(nl_endpoint_t *ep);

/* ----------------------------------------------------------------------- */
/* I/O                                                                      */
/* ----------------------------------------------------------------------- */

/* Enqueue `len` bytes for delivery to `peer` on `channel` using `delivery`.
 * Thread-safe: may be called concurrently from multiple threads, including
 * concurrently with nl_poll_event(). Copies `data` internally; the caller's
 * buffer may be reused/freed immediately after this returns.
 *
 * Equivalent to nl_send_ex(..., NL_PRIORITY_NORMAL). The send may be
 * deferred internally (congestion window, peer receive window, or rate
 * limit) and still return NL_OK -- NL_ERR_QUEUE_FULL is only returned
 * when the per-connection deferred queue itself is full. */
NL_API nl_result_t nl_send(nl_endpoint_t *ep, nl_peer_id_t peer, uint8_t channel,
                            nl_delivery_t delivery, const uint8_t *data, size_t len);

/* Like nl_send, with an explicit priority (0..255, higher = more urgent).
 * When the connection's send window is closed, messages are queued and
 * flushed highest-priority-first as window/rate budget opens. */
NL_API nl_result_t nl_send_ex(nl_endpoint_t *ep, nl_peer_id_t peer, uint8_t channel,
                              nl_delivery_t delivery, const uint8_t *data, size_t len,
                              uint8_t priority);

/* Pop the next event, waiting up to timeout_ms for one to arrive (0 = don't
 * block, -1 = block forever). Returns true if an event was written to *out.
 * `out->data` (for NL_EVENT_DATA) is only valid until the next call to
 * nl_poll_event on this endpoint -- copy it if you need it longer. */
NL_API bool nl_poll_event(nl_endpoint_t *ep, nl_event_t *out, int timeout_ms);

/* ----------------------------------------------------------------------- */
/* Discovery / lobby                                                       */
/* ----------------------------------------------------------------------- */

/* Server: start responding to LAN discovery broadcasts on discovery_port. */
NL_API nl_result_t nl_discovery_enable(nl_endpoint_t *ep, uint16_t discovery_port);

/* Client: broadcast a discovery probe on the LAN and collect replies as
 * NL_EVENT_DISCOVERY_REPLY events over the next ~timeout_ms. */
NL_API nl_result_t nl_discovery_probe(nl_endpoint_t *ep, uint16_t discovery_port, int timeout_ms);

/* ----------------------------------------------------------------------- */
/* Introspection                                                           */
/* ----------------------------------------------------------------------- */

NL_API bool nl_peer_address(nl_endpoint_t *ep, nl_peer_id_t peer, nl_address_t *out);
NL_API uint32_t nl_peer_rtt_ms(nl_endpoint_t *ep, nl_peer_id_t peer);
NL_API uint32_t nl_peer_count(nl_endpoint_t *ep);

/* Per-peer counters and timing estimates: sent/received packet and byte
 * counts, retransmissions (RTO-triggered and fast-retransmit combined),
 * duplicate/replayed packets rejected, and RTT statistics (smoothed RTT,
 * smoothed RTT variance, and the currently-derived retransmit timeout --
 * see the README's Architecture section for the estimation algorithm).
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
} nl_peer_stats_t;

/* Copy out a snapshot of `peer`'s counters and RTT estimates. Returns
 * false if `peer` is not a currently-known connection. Thread-safe. */
NL_API bool nl_peer_stats(nl_endpoint_t *ep, nl_peer_id_t peer, nl_peer_stats_t *out);

/* Copy out the capability bits negotiated with `peer` during the
 * handshake (bitwise AND of both peers' advertised sets). Returns false
 * if `peer` is not a currently-known connection. Thread-safe. */
NL_API bool nl_peer_capabilities(nl_endpoint_t *ep, nl_peer_id_t peer, uint32_t *out_caps);

#ifdef __cplusplus
}
#endif

#endif /* NETLINK_H */
