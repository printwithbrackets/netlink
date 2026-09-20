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
 * connect to each other rather than risk misinterpreting bytes. */
#define NL_PROTOCOL_VERSION 1

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
    uint32_t       max_connections;     /* server only; 0 = library default (64) */
    uint32_t       connection_timeout_ms; /* no traffic for this long => disconnect; 0 = default (10000) */
    uint32_t       keepalive_interval_ms; /* 0 = default (1000) */
    bool           encryption_enabled;  /* default true. Disabling is for local/LAN debugging ONLY. */
    const char    *server_name;         /* used in discovery responses, optional */
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
 * NL_EVENT_CONNECTED or NL_EVENT_CONNECT_FAILED event. */
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
 * buffer may be reused/freed immediately after this returns. */
NL_API nl_result_t nl_send(nl_endpoint_t *ep, nl_peer_id_t peer, uint8_t channel,
                            nl_delivery_t delivery, const uint8_t *data, size_t len);

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

#ifdef __cplusplus
}
#endif

#endif /* NETLINK_H */
