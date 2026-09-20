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

    uint32_t connection_timeout_ms;
    uint32_t keepalive_interval_ms;

    bool handshake_confirmed; /* client-side: has CONNECT_ACCEPTED been seen yet */

    pthread_mutex_t lock;
} nl_connection_t;

nl_connection_t *nl_connection_create(nl_peer_id_t id, const struct sockaddr_storage *addr, socklen_t addr_len,
                                       bool is_client_side, uint8_t channel_count,
                                       const uint8_t send_key[NL_KEY_SIZE], const uint8_t recv_key[NL_KEY_SIZE],
                                       const uint8_t send_salt[12], const uint8_t recv_salt[12],
                                       uint32_t connection_timeout_ms, uint32_t keepalive_interval_ms,
                                       uint64_t now_ms);
void nl_connection_destroy(nl_connection_t *conn);

/* Encrypt and emit `data`/`len` on `channel`/`delivery`. Thread-safe. */
nl_result_t nl_connection_send(nl_connection_t *conn, uint8_t channel, nl_delivery_t delivery,
                                const uint8_t *data, size_t len, uint64_t now_ms,
                                const nl_conn_callbacks_t *cb);

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
 * encrypted packet. */
void nl_connection_send_handshake_complete(nl_connection_t *conn, const nl_conn_callbacks_t *cb);

uint32_t nl_connection_rtt_ms(nl_connection_t *conn);

#endif /* NETLINK_CONNECTION_H */
