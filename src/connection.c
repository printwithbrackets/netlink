#include "connection.h"
#include "byteorder.h"
#include <stdlib.h>
#include <string.h>

#define NL_DEFAULT_RTT_MS 200
#define NL_MIN_RTO_MS 100
#define NL_MAX_RETRIES 15
#define NL_ENCRYPTED_PACKET_SCRATCH (NL_MAX_PACKET_SIZE + NL_ENC_HEADER_SIZE + NL_GCM_TAG_SIZE + 64)

nl_connection_t *nl_connection_create(nl_peer_id_t id, const struct sockaddr_storage *addr, socklen_t addr_len,
                                       bool is_client_side, uint8_t channel_count,
                                       const uint8_t send_key[NL_KEY_SIZE], const uint8_t recv_key[NL_KEY_SIZE],
                                       const uint8_t send_salt[12], const uint8_t recv_salt[12],
                                       uint32_t connection_timeout_ms, uint32_t keepalive_interval_ms,
                                       uint64_t now_ms) {
    nl_connection_t *conn = (nl_connection_t *)calloc(1, sizeof(nl_connection_t));
    if (!conn) return NULL;

    conn->id = id;
    memcpy(&conn->addr, addr, sizeof(*addr));
    conn->addr_len = addr_len;
    conn->state = NL_CONN_CONNECTED;
    conn->is_client_side = is_client_side;

    memcpy(conn->send_key, send_key, NL_KEY_SIZE);
    memcpy(conn->recv_key, recv_key, NL_KEY_SIZE);
    memcpy(conn->send_salt, send_salt, 12);
    memcpy(conn->recv_salt, recv_salt, 12);
    conn->send_counter = 0;
    nl_replay_window_init(&conn->recv_replay);

    conn->channel_count = channel_count;
    conn->channels = (nl_channel_t *)calloc(channel_count, sizeof(nl_channel_t));
    if (!conn->channels) { free(conn); return NULL; }
    for (uint8_t i = 0; i < channel_count; i++) nl_channel_init(&conn->channels[i]);

    conn->last_recv_time_ms = now_ms;
    conn->last_send_time_ms = now_ms;
    conn->rtt_ms = NL_DEFAULT_RTT_MS;
    conn->rto_ms = NL_DEFAULT_RTT_MS * 2;
    if (conn->rto_ms < NL_MIN_RTO_MS) conn->rto_ms = NL_MIN_RTO_MS;

    conn->connection_timeout_ms = connection_timeout_ms;
    conn->keepalive_interval_ms = keepalive_interval_ms;

    if (pthread_mutex_init(&conn->lock, NULL) != 0) {
        free(conn->channels);
        free(conn);
        return NULL;
    }

    return conn;
}

void nl_connection_destroy(nl_connection_t *conn) {
    if (!conn) return;
    for (uint8_t i = 0; i < conn->channel_count; i++) nl_channel_free(&conn->channels[i]);
    free(conn->channels);
    pthread_mutex_destroy(&conn->lock);
    /* Best-effort zeroing of key material before freeing. */
    memset(conn->send_key, 0, sizeof(conn->send_key));
    memset(conn->recv_key, 0, sizeof(conn->recv_key));
    free(conn);
}

/* ---- encryption plumbing (caller must hold conn->lock) ---- */

static void encrypt_and_emit(nl_connection_t *conn, uint8_t type, const uint8_t *plaintext, size_t pt_len,
                              const nl_conn_callbacks_t *cb) {
    uint8_t packet[NL_ENCRYPTED_PACKET_SCRATCH];
    size_t off = 0;
    packet[off++] = type;
    nl_put_u64(packet + off, conn->id); off += 8;
    uint64_t counter = conn->send_counter++;
    nl_put_u64(packet + off, counter); off += 8;

    uint8_t nonce[12];
    nl_nonce_build(conn->send_salt, counter, nonce);

    uint8_t tag[16];
    /* AAD is exactly the cleartext header just written (type + connection_id + nonce_counter). */
    if (!nl_crypto_aead_encrypt(conn->send_key, nonce, packet, off, plaintext, pt_len, packet + off, tag)) {
        return; /* encryption failure: fail closed, drop the packet rather than send unprotected data */
    }
    off += pt_len;
    memcpy(packet + off, tag, 16);
    off += 16;

    cb->send_wire(cb->ctx, conn->id, packet, off);
}

typedef struct {
    nl_connection_t *conn;
    const nl_conn_callbacks_t *cb;
} emit_ctx_t;

static void on_channel_emit(void *ctx, const uint8_t *wire_payload, uint16_t len) {
    emit_ctx_t *e = (emit_ctx_t *)ctx;
    encrypt_and_emit(e->conn, NL_PKT_DATA, wire_payload, len, e->cb);
}

nl_result_t nl_connection_send(nl_connection_t *conn, uint8_t channel, nl_delivery_t delivery,
                                const uint8_t *data, size_t len, uint64_t now_ms,
                                const nl_conn_callbacks_t *cb) {
    if (channel >= conn->channel_count) return NL_ERR_CHANNEL_OUT_OF_RANGE;

    pthread_mutex_lock(&conn->lock);
    if (conn->state != NL_CONN_CONNECTED) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_NOT_CONNECTED;
    }
    emit_ctx_t ectx = { conn, cb };
    nl_result_t r = nl_channel_send(&conn->channels[channel], now_ms, channel, delivery, data, len,
                                     on_channel_emit, &ectx);
    if (r == NL_OK) conn->last_send_time_ms = now_ms;
    pthread_mutex_unlock(&conn->lock);
    return r;
}

typedef struct {
    nl_peer_id_t peer;
    const nl_conn_callbacks_t *cb;
} deliver_ctx_t;

static void on_channel_deliver(void *ctx, uint8_t channel_id, nl_delivery_t delivery,
                                const uint8_t *data, uint32_t len) {
    deliver_ctx_t *d = (deliver_ctx_t *)ctx;
    d->cb->on_data(d->cb->ctx, d->peer, channel_id, delivery, data, len);
}

nl_result_t nl_connection_on_packet(nl_connection_t *conn, uint8_t type,
                                     const uint8_t *enc_body, size_t enc_body_len,
                                     uint64_t now_ms, const nl_conn_callbacks_t *cb) {
    if (enc_body_len < 8 + 8 + NL_GCM_TAG_SIZE) return NL_ERR_PROTOCOL_MISMATCH;

    uint64_t counter = nl_get_u64(enc_body + 8);
    size_t ct_len = enc_body_len - 8 - 8 - NL_GCM_TAG_SIZE;
    const uint8_t *ciphertext = enc_body + 16;
    const uint8_t *tag = enc_body + 16 + ct_len;

    pthread_mutex_lock(&conn->lock);

    if (conn->state != NL_CONN_CONNECTED) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_NOT_CONNECTED;
    }

    /* Cheap non-mutating pre-check to avoid wasting CPU decrypting an
     * obvious replay. The window is only actually updated below, AFTER
     * authentication succeeds -- see the comment on
     * nl_replay_window_would_accept() for why the ordering matters. */
    if (!nl_replay_window_would_accept(&conn->recv_replay, counter)) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_PROTOCOL_MISMATCH;
    }

    uint8_t nonce[12];
    nl_nonce_build(conn->recv_salt, counter, nonce);

    uint8_t aad[17];
    aad[0] = type;
    memcpy(aad + 1, enc_body, 16); /* connection_id(8) + nonce_counter(8) */

    uint8_t plaintext[NL_MAX_PACKET_SIZE + NL_FRAGMENT_HEADER_SIZE + 64];
    if (ct_len > sizeof(plaintext)) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_MESSAGE_TOO_LARGE;
    }
    if (!nl_crypto_aead_decrypt(conn->recv_key, nonce, aad, sizeof(aad), ciphertext, ct_len, tag, plaintext)) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_CRYPTO; /* bad tag: tampered, wrong key, or corrupted -- drop */
    }

    /* Authenticated: now it's safe to commit this counter to the replay window. */
    if (!nl_replay_window_check(&conn->recv_replay, counter)) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_PROTOCOL_MISMATCH; /* lost a race with another thread's identical packet */
    }

    conn->last_recv_time_ms = now_ms;

    nl_result_t result = NL_OK;
    bool just_confirmed = false;
    switch (type) {
        case NL_PKT_DATA: {
            deliver_ctx_t dctx = { conn->id, cb };
            /* Route by the channel_id embedded in the plaintext (byte 0
             * of the DATA payload) into that channel's state. */
            if (ct_len < 1) { result = NL_ERR_PROTOCOL_MISMATCH; break; }
            uint8_t channel_id = plaintext[0];
            if (channel_id >= conn->channel_count) { result = NL_ERR_CHANNEL_OUT_OF_RANGE; break; }
            nl_channel_on_receive(&conn->channels[channel_id], now_ms, plaintext, (uint16_t)ct_len,
                                   on_channel_deliver, &dctx);
            break;
        }
        case NL_PKT_KEEPALIVE:
            /* Nothing to do beyond the last_recv_time_ms update above --
             * keepalives exist purely to keep the connection from idling
             * out and to let both sides estimate RTT. */
            break;
        case NL_PKT_CONNECT_ACCEPTED:
            /* Client-side handshake confirmation. Harmless no-op if this
             * ever reaches a server-side connection object (servers never
             * receive this type from a well-behaved peer; it's simply
             * ignored beyond the authentication that already happened). */
            if (!conn->handshake_confirmed) {
                conn->handshake_confirmed = true;
                just_confirmed = true;
            }
            break;
        case NL_PKT_DISCONNECT:
            conn->state = NL_CONN_DISCONNECTED;
            break;
        default:
            result = NL_ERR_PROTOCOL_MISMATCH;
            break;
    }

    bool became_disconnected = (conn->state == NL_CONN_DISCONNECTED);
    pthread_mutex_unlock(&conn->lock);

    if (just_confirmed && cb->on_connected) {
        cb->on_connected(cb->ctx, conn->id);
    }
    if (became_disconnected) {
        cb->on_disconnected(cb->ctx, conn->id, NL_OK); /* peer-initiated graceful close */
    }

    return result;
}

typedef struct {
    nl_connection_t *conn;
    const nl_conn_callbacks_t *cb;
} retransmit_ctx_t;

static void on_channel_retransmit(void *ctx, const uint8_t *wire_payload, uint16_t len) {
    retransmit_ctx_t *r = (retransmit_ctx_t *)ctx;
    encrypt_and_emit(r->conn, NL_PKT_DATA, wire_payload, len, r->cb);
}

void nl_connection_tick(nl_connection_t *conn, uint64_t now_ms, const nl_conn_callbacks_t *cb) {
    pthread_mutex_lock(&conn->lock);
    if (conn->state != NL_CONN_CONNECTED) {
        pthread_mutex_unlock(&conn->lock);
        return;
    }

    /* Idle timeout. */
    if (now_ms - conn->last_recv_time_ms > conn->connection_timeout_ms) {
        conn->state = NL_CONN_DISCONNECTED;
        pthread_mutex_unlock(&conn->lock);
        cb->on_disconnected(cb->ctx, conn->id, NL_ERR_TIMEOUT);
        return;
    }

    /* Retransmission scan across every channel's reliable lanes. */
    retransmit_ctx_t rctx = { conn, cb };
    bool any_gave_up = false;
    for (uint8_t c = 0; c < conn->channel_count; c++) {
        bool give_up = false;
        nl_channel_tick(&conn->channels[c], c, now_ms, conn->rto_ms, NL_MAX_RETRIES,
                         on_channel_retransmit, &rctx, &give_up);
        any_gave_up = any_gave_up || give_up;
    }

    /* Idle keepalive so a channel with no application traffic still gets
     * timely acks and RTT samples, and the peer's idle timer keeps resetting. */
    if (now_ms - conn->last_send_time_ms >= conn->keepalive_interval_ms) {
        uint8_t empty[1] = {0};
        encrypt_and_emit(conn, NL_PKT_KEEPALIVE, empty, 0, cb);
        conn->last_send_time_ms = now_ms;
    }

    bool give_up_disconnect = any_gave_up;
    if (give_up_disconnect) conn->state = NL_CONN_DISCONNECTED;
    pthread_mutex_unlock(&conn->lock);

    if (give_up_disconnect) {
        cb->on_disconnected(cb->ctx, conn->id, NL_ERR_TIMEOUT);
    }
}

void nl_connection_send_disconnect(nl_connection_t *conn, uint64_t now_ms, const nl_conn_callbacks_t *cb) {
    pthread_mutex_lock(&conn->lock);
    if (conn->state == NL_CONN_CONNECTED) {
        uint8_t empty[1] = {0};
        encrypt_and_emit(conn, NL_PKT_DISCONNECT, empty, 0, cb);
        conn->state = NL_CONN_DISCONNECTED;
        conn->last_send_time_ms = now_ms;
    }
    pthread_mutex_unlock(&conn->lock);
}

void nl_connection_send_handshake_complete(nl_connection_t *conn, const nl_conn_callbacks_t *cb) {
    pthread_mutex_lock(&conn->lock);
    uint8_t empty[1] = {0};
    encrypt_and_emit(conn, NL_PKT_CONNECT_ACCEPTED, empty, 0, cb);
    pthread_mutex_unlock(&conn->lock);
}

uint32_t nl_connection_rtt_ms(nl_connection_t *conn) {
    pthread_mutex_lock(&conn->lock);
    uint32_t rtt = conn->rtt_ms;
    pthread_mutex_unlock(&conn->lock);
    return rtt;
}
