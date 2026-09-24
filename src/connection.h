/* connection.h - an established (post-handshake) peer connection.
 *
 * Owns the per-connection encryption keys/nonce state, the channel array,
 * and a mutex that serializes all access to that state. This is the
 * thread-safety boundary: nl_send() (callable from any user thread) and
 * the endpoint's I/O thread (processing incoming packets and running
 * retransmission ticks) both go through nl_connection_send /
 * nl_connection_on_packet / nl_connection_tick, all of which take the
 * connection's lock internally. channel.c itself assumes single-threaded
 * access -- connection.c is what makes that safe under concurrency.
 */
#ifndef NETLINK_CONNECTION_H
#define NETLINK_CONNECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "channel.h"
#include "crypto.h"
#include "protocol.h"
#include "socket_compat.h"
#include "../include/netlink.h"

typedef enum {
    NL_CONN_CONNECTED,
    NL_CONN_DISCONNECTED,
} nl_conn_state_t;

/* Per-connection counters and timing estimates, exposed via
 * nl_connection_get_stats() / the public nl_peer_stats() API. */
typedef struct {
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t retransmits;         /* RTO-triggered + fast-retransmit-triggered, combined */
    uint64_t duplicates_received; /* wire-level replays rejected (see recv_replay in nl_connection_t) */
    uint32_t rtt_ms;              /* smoothed RTT (SRTT), Jacobson/Karels */
    uint32_t rtt_var_ms;          /* smoothed RTT variance (RTTVAR) */
    uint32_t rto_ms;              /* current retransmission timeout, derived from the above */
} nl_connection_stats_t;

/* One application message parked because the send window (congestion,
 * peer receive window) or the rate limiter wouldn't let it out yet.
 * Linked in descending priority order (stable FIFO within a priority). */
typedef struct nl_deferred_msg {
    uint8_t channel;
    uint8_t delivery; /* nl_delivery_t */
    uint8_t priority;
    uint16_t len;
    uint8_t *data;
    struct nl_deferred_msg *next;
} nl_deferred_msg_t;

#define NL_CWND_INITIAL_PACKETS 10    /* RFC 6928-style initial window */
#define NL_SSTHRESH_INITIAL_PACKETS 64
#define NL_CWND_MAX_PACKETS 256       /* matches send-ring depth; above this
                                       * the ring itself becomes the limit */
#define NL_DEFERRED_MAX_MSGS 128
#define NL_DEFERRED_MAX_BYTES (64 * 1024)
/* NL_RECV_WINDOW_DEFAULT lives in protocol.h (shared with channel tests). */
#define NL_RECV_WINDOW_MAX 65535u

/* A generic sink for events/packets a connection needs to hand back up to
 * the endpoint (queueing an event, or sending bytes on the wire). Kept as
 * function pointers + a context so connection.c has zero dependency on
 * endpoint.c's internals. */
typedef void (*nl_conn_deliver_event_fn)(void *ctx, nl_peer_id_t peer, uint8_t channel,
                                          nl_delivery_t delivery, const uint8_t *data, uint32_t len);
typedef void (*nl_conn_disconnected_fn)(void *ctx, nl_peer_id_t peer, nl_result_t reason);
typedef void (*nl_conn_send_wire_fn)(void *ctx, nl_peer_id_t peer, const uint8_t *packet, size_t len);
/* Client-side only: fired exactly once, the first time the handshake is
 * confirmed end-to-end (this connection successfully decrypted a
 * CONNECT_ACCEPTED). Until this fires, the client shouldn't consider
 * itself connected -- having sent CONNECT_RESPONSE only means it HOPES
 * the server accepted, not that it has confirmed it did. */
typedef void (*nl_conn_connected_fn)(void *ctx, nl_peer_id_t peer);

typedef struct {
    nl_conn_deliver_event_fn on_data;
    nl_conn_disconnected_fn  on_disconnected;
    nl_conn_send_wire_fn     send_wire; /* actually put bytes on the socket */
    nl_conn_connected_fn     on_connected; /* may be NULL (server side doesn't need it) */
    void *ctx;
} nl_conn_callbacks_t;

typedef struct nl_connection {
    nl_peer_id_t id; /* == wire connection_id */
    struct sockaddr_storage addr;
    socklen_t addr_len;

    nl_conn_state_t state;
    bool is_client_side; /* determines which key is c2s vs s2c for us */

    uint8_t send_key[NL_KEY_SIZE];
    uint8_t recv_key[NL_KEY_SIZE];
    uint8_t send_salt[12];
    uint8_t recv_salt[12];
    uint64_t send_counter;
    nl_replay_window_t recv_replay;

    nl_channel_t *channels; /* heap array, channel_count entries */
    uint8_t channel_count;

    uint64_t last_recv_time_ms;
    uint64_t last_send_time_ms;
    uint32_t rtt_ms;           /* smoothed estimate (EWMA), starts at a safe default */
    uint32_t rto_ms;           /* derived retransmit timeout, >= rtt_ms with margin */
    double   srtt_ms;          /* Jacobson/Karels smoothed RTT, higher precision than rtt_ms */
    double   rttvar_ms;        /* Jacobson/Karels smoothed RTT variance */
    bool     rtt_initialized;

    nl_connection_stats_t stats;

    uint32_t connection_timeout_ms;
    uint32_t keepalive_interval_ms;

    /* Congestion control (packet-based Reno): cwnd/ssthresh count reliable
     * packets in flight across all channels' send rings. Unreliable traffic
     * does not consume cwnd (it has no ack clock to ride). */
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t cwnd_ack_accum; /* congestion-avoidance: +1 cwnd per full window of acks */

    /* Flow control: peer's last advertised receive window (bytes of DATA
     * they'll still buffer), and our own receive-window accounting so we
     * can advertise accurately. peer_rwnd starts at the default until the
     * first DATA from the peer carries a real value. */
    uint16_t peer_rwnd;
    uint32_t recv_window_size;  /* configured local window capacity (bytes) */
    uint32_t recv_window_used;  /* payload bytes currently queued for the app */

    /* Sender-side rate limit (payload bytes/sec; 0 = off). Token bucket;
     * retransmits and keepalives bypass it so loss recovery is never starved. */
    uint32_t rate_bps;
    double   rate_tokens;
    uint64_t rate_last_refill_ms;

    /* Deferred sends waiting for window/rate budget, priority-sorted. */
    nl_deferred_msg_t *deferred_head;
    uint32_t deferred_count;
    uint32_t deferred_bytes;

    /* Negotiated handshake capabilities (AND of both peers' advertised sets). */
    uint32_t capabilities;

    bool handshake_confirmed; /* client-side: has CONNECT_ACCEPTED been seen yet */
    /* Server-side: CONNECT_ACCEPTED retransmission bookkeeping. The client
     * may silently drop the single ACCEPTED datagram; until it confirms by
     * successfully decrypting one, the server must be willing to resend. */
    uint64_t accept_sent_ms;      /* when ACCEPTED was last put on the wire */
    uint32_t accept_retries_left; /* countdown; 0 = stop retrying this handshake */

    pthread_mutex_t lock;
} nl_connection_t;

nl_connection_t *nl_connection_create(nl_peer_id_t id, const struct sockaddr_storage *addr, socklen_t addr_len,
                                       bool is_client_side, uint8_t channel_count,
                                       const uint8_t send_key[NL_KEY_SIZE], const uint8_t recv_key[NL_KEY_SIZE],
                                       const uint8_t send_salt[12], const uint8_t recv_salt[12],
                                       uint32_t connection_timeout_ms, uint32_t keepalive_interval_ms,
                                       uint64_t now_ms);
void nl_connection_destroy(nl_connection_t *conn);

/* Encrypt and emit `data`/`len` on `channel`/`delivery` with `priority`.
 * Thread-safe. May defer internally when the congestion window, the peer's
 * receive window, or the rate limiter is exhausted (still returns NL_OK);
 * returns NL_ERR_QUEUE_FULL only if the deferred queue bounds are hit.
 * `now_ms` is required (used for rate-limit refill). */
nl_result_t nl_connection_send(nl_connection_t *conn, uint8_t channel, nl_delivery_t delivery,
                                const uint8_t *data, size_t len, uint8_t priority,
                                uint64_t now_ms, const nl_conn_callbacks_t *cb);

/* Decrypt and process one received encrypted packet (DATA, KEEPALIVE, or
 * DISCONNECT -- `type` already parsed from the cleartext byte 0 by the
 * caller). `enc_body` points at the connection_id+nonce_counter+ciphertext+tag
 * region (everything from byte 1 onward). Thread-safe. */
nl_result_t nl_connection_on_packet(nl_connection_t *conn, uint8_t type,
                                     const uint8_t *enc_body, size_t enc_body_len,
                                     uint64_t now_ms, const nl_conn_callbacks_t *cb);

/* Run retransmission scanning, idle-keepalive, and timeout checks. May
 * invoke cb->on_disconnected if the connection has timed out. Thread-safe. */
void nl_connection_tick(nl_connection_t *conn, uint64_t now_ms, const nl_conn_callbacks_t *cb);

/* Best-effort graceful close: sends a DISCONNECT notification. */
void nl_connection_send_disconnect(nl_connection_t *conn, uint64_t now_ms, const nl_conn_callbacks_t *cb);

/* Used only by endpoint.c to send the CONNECT_ACCEPTED packet that
 * completes a handshake: it must be encrypted with the connection's
 * freshly-derived keys (both to serve as key confirmation -- if the
 * client can decrypt it, both sides derived matching keys -- and because
 * every packet after the cleartext handshake messages is encrypted by
 * policy). Carries no payload; the client learns its assigned identity
 * from the packet's own cleartext connection_id field, same as any other
 * encrypted packet.
 *
 * `is_retry` distinguishes the initial send (arms accept_retries_left /
 * accept_sent_ms for the tick-driven resend loop) from a retransmission
 * (just puts another copy on the wire without re-arming the budget). */
void nl_connection_send_handshake_complete(nl_connection_t *conn, uint64_t now_ms,
                                            bool is_retry, const nl_conn_callbacks_t *cb);

uint32_t nl_connection_rtt_ms(nl_connection_t *conn);

/* Copy out a snapshot of this connection's counters and RTT estimates.
 * Thread-safe. */
void nl_connection_get_stats(nl_connection_t *conn, nl_connection_stats_t *out);

/* Negotiated capability bits (see NL_CAP_* in netlink.h). Thread-safe. */
uint32_t nl_connection_capabilities(nl_connection_t *conn);

/* Current receive window we should advertise to the peer (bytes still
 * available under recv_window_size). Caller must hold conn->lock (or be
 * the sole user before the connection is published). */
uint16_t nl_connection_adv_window(nl_connection_t *conn);

/* Apply endpoint-level receive-window accounting when the app consumes a
 * DATA event (called from nl_poll_event). Thread-safe. */
void nl_connection_consume_window(nl_connection_t *conn, uint32_t bytes);

#endif /* NETLINK_CONNECTION_H */
