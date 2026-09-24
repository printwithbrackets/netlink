#include "connection.h"
#include "byteorder.h"
#include <stdlib.h>
#include <string.h>

#define NL_DEFAULT_RTT_MS 200
#define NL_MIN_RTO_MS 100
#define NL_MAX_RTO_MS 10000
#define NL_MAX_RETRIES 15
#define NL_ENCRYPTED_PACKET_SCRATCH (NL_MAX_PACKET_SIZE + NL_ENC_HEADER_SIZE + NL_GCM_TAG_SIZE + 64)
/* How many times (including the initial send) the server will put
 * CONNECT_ACCEPTED on the wire before giving up on the client hearing it.
 * Combined with NL_HANDSHAKE_RETRY_MS below this covers multi-second
 * loss windows without unbounded resend if the client is gone. */
#define NL_ACCEPT_RETRIES 8
#define NL_HANDSHAKE_RETRY_MS 250

/* Jacobson/Karels smoothed RTT + RTTVAR update (the same algorithm TCP's
 * RTO estimation uses, RFC 6298), fed only by clean samples -- see
 * seqbuf.h's nl_send_ring_ack() doc comment on why retransmitted and
 * bitfield-only-acked packets are never used as samples (Karn's
 * algorithm). alpha=1/8, beta=1/4 are the RFC's standard gains. */
static void update_rtt(nl_connection_t *conn, uint32_t sample_ms) {
    double sample = (double)sample_ms;
    if (!conn->rtt_initialized) {
        conn->srtt_ms = sample;
        conn->rttvar_ms = sample / 2.0;
        conn->rtt_initialized = true;
    } else {
        double diff = sample - conn->srtt_ms;
        double abs_diff = diff < 0 ? -diff : diff;
        conn->rttvar_ms += 0.25 * (abs_diff - conn->rttvar_ms);
        conn->srtt_ms += 0.125 * diff;
    }
    double rto = conn->srtt_ms + 4.0 * conn->rttvar_ms;
    if (rto < NL_MIN_RTO_MS) rto = NL_MIN_RTO_MS;
    if (rto > NL_MAX_RTO_MS) rto = NL_MAX_RTO_MS;
    conn->rto_ms = (uint32_t)rto;
    conn->rtt_ms = (uint32_t)conn->srtt_ms;
}

/* ---- congestion control (packet Reno, reliable traffic only) ---- */

static uint32_t reliable_in_flight(nl_connection_t *conn) {
    uint32_t n = 0;
    for (uint8_t c = 0; c < conn->channel_count; c++) {
        for (int d = NL_RELIABLE_UNORDERED; d <= NL_RELIABLE_ORDERED; d++) {
            nl_lane_t *lane = &conn->channels[c].lanes[d];
            if (lane->send_ring_init) n += lane->send_ring.unacked_count;
        }
    }
    return n;
}

static void cc_on_acks(nl_connection_t *conn, uint32_t newly_acked) {
    for (uint32_t i = 0; i < newly_acked; i++) {
        if (conn->cwnd < conn->ssthresh) {
            conn->cwnd++; /* slow start: +1 per ack */
        } else {
            /* Congestion avoidance: +1 per full window of acks (~1 per RTT). */
            conn->cwnd_ack_accum++;
            if (conn->cwnd_ack_accum >= conn->cwnd) {
                conn->cwnd_ack_accum = 0;
                if (conn->cwnd < NL_CWND_MAX_PACKETS) conn->cwnd++;
            }
        }
        if (conn->cwnd > NL_CWND_MAX_PACKETS) conn->cwnd = NL_CWND_MAX_PACKETS;
    }
}

/* Loss signal: RTO resets cwnd to 1 (slow start); fast retransmit enters
 * recovery at half window (ssthresh). `fast` selects which. */
static void cc_on_loss(nl_connection_t *conn, bool fast) {
    uint32_t half = conn->cwnd / 2;
    if (half < 2) half = 2;
    conn->ssthresh = half;
    conn->cwnd_ack_accum = 0;
    conn->cwnd = fast ? half : 1;
    if (conn->cwnd > NL_CWND_MAX_PACKETS) conn->cwnd = NL_CWND_MAX_PACKETS;
}

/* ---- rate limiting (token bucket over payload bytes) ---- */

static void rate_refill(nl_connection_t *conn, uint64_t now_ms) {
    if (conn->rate_bps == 0) return;
    if (now_ms < conn->rate_last_refill_ms) conn->rate_last_refill_ms = now_ms;
    double elapsed_s = (double)(now_ms - conn->rate_last_refill_ms) / 1000.0;
    if (elapsed_s <= 0.0) return;
    conn->rate_tokens += elapsed_s * (double)conn->rate_bps;
    if (conn->rate_tokens > (double)conn->rate_bps) {
        conn->rate_tokens = (double)conn->rate_bps; /* 1s burst cap */
    }
    conn->rate_last_refill_ms = now_ms;
}

/* ---- deferred send queue (priority-sorted) ---- */

static void deferred_free_all(nl_connection_t *conn) {
    nl_deferred_msg_t *m = conn->deferred_head;
    while (m) {
        nl_deferred_msg_t *next = m->next;
        free(m->data);
        free(m);
        m = next;
    }
    conn->deferred_head = NULL;
    conn->deferred_count = 0;
    conn->deferred_bytes = 0;
}

/* Insert keeping descending priority (higher number first); stable FIFO
 * within equal priority by inserting after all strictly-greater entries. */
static bool deferred_push(nl_connection_t *conn, uint8_t channel, nl_delivery_t delivery,
                          uint8_t priority, const uint8_t *data, size_t len) {
    if (conn->deferred_count >= NL_DEFERRED_MAX_MSGS) return false;
    if (conn->deferred_bytes + len > NL_DEFERRED_MAX_BYTES) return false;
    if (len > UINT16_MAX) return false;

    nl_deferred_msg_t *m = (nl_deferred_msg_t *)calloc(1, sizeof(*m));
    if (!m) return false;
    m->data = (uint8_t *)malloc(len ? len : 1);
    if (!m->data) { free(m); return false; }
    if (len) memcpy(m->data, data, len);
    m->channel = channel;
    m->delivery = (uint8_t)delivery;
    m->priority = priority;
    m->len = (uint16_t)len;
    m->next = NULL;

    if (!conn->deferred_head || conn->deferred_head->priority < priority) {
        m->next = conn->deferred_head;
        conn->deferred_head = m;
    } else {
        nl_deferred_msg_t *cur = conn->deferred_head;
        while (cur->next && cur->next->priority >= priority) cur = cur->next;
        m->next = cur->next;
        cur->next = m;
    }
    conn->deferred_count++;
    conn->deferred_bytes += (uint32_t)len;
    return true;
}

static nl_deferred_msg_t *deferred_pop(nl_connection_t *conn) {
    nl_deferred_msg_t *m = conn->deferred_head;
    if (!m) return NULL;
    conn->deferred_head = m->next;
    conn->deferred_count--;
    conn->deferred_bytes -= m->len;
    m->next = NULL;
    return m;
}

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
    conn->accept_sent_ms = 0;
    conn->accept_retries_left = 0;

    conn->connection_timeout_ms = connection_timeout_ms;
    conn->keepalive_interval_ms = keepalive_interval_ms;

    conn->cwnd = NL_CWND_INITIAL_PACKETS;
    conn->ssthresh = NL_SSTHRESH_INITIAL_PACKETS;
    conn->cwnd_ack_accum = 0;
    conn->peer_rwnd = (uint16_t)NL_RECV_WINDOW_DEFAULT;
    conn->recv_window_size = NL_RECV_WINDOW_DEFAULT;
    conn->recv_window_used = 0;
    conn->rate_bps = 0;
    conn->rate_tokens = 0.0;
    conn->rate_last_refill_ms = now_ms;
    conn->deferred_head = NULL;
    conn->deferred_count = 0;
    conn->deferred_bytes = 0;
    conn->capabilities = 0;

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
    deferred_free_all(conn);
    pthread_mutex_destroy(&conn->lock);
    /* Best-effort zeroing of key material before freeing. */
    memset(conn->send_key, 0, sizeof(conn->send_key));
    memset(conn->recv_key, 0, sizeof(conn->recv_key));
    free(conn);
}

/* ---- encryption plumbing (caller must hold conn->lock) ---- */

static void encrypt_and_emit(nl_connection_t *conn, uint8_t type, const uint8_t *plaintext, size_t pt_len,
                              bool is_retransmit, const nl_conn_callbacks_t *cb) {
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

    conn->stats.packets_sent++;
    conn->stats.bytes_sent += off;
    if (is_retransmit) conn->stats.retransmits++;

    cb->send_wire(cb->ctx, conn->id, packet, off);
}

typedef struct {
    nl_connection_t *conn;
    const nl_conn_callbacks_t *cb;
} emit_ctx_t;

static void on_channel_emit(void *ctx, const uint8_t *wire_payload, uint16_t len) {
    emit_ctx_t *e = (emit_ctx_t *)ctx;
    encrypt_and_emit(e->conn, NL_PKT_DATA, wire_payload, len, /*is_retransmit*/ false, e->cb);
}

typedef struct {
    nl_connection_t *conn;
    const nl_conn_callbacks_t *cb;
} retransmit_ctx_t;

/* Shared by both RTO-triggered retransmission (nl_connection_tick) and
 * receive-triggered fast retransmit (nl_connection_on_packet's DATA
 * case) -- both reconstruct-and-resend a specific unacked sequence, and
 * both count as a retransmit for stats purposes. */
static void on_channel_retransmit(void *ctx, const uint8_t *wire_payload, uint16_t len) {
    retransmit_ctx_t *r = (retransmit_ctx_t *)ctx;
    encrypt_and_emit(r->conn, NL_PKT_DATA, wire_payload, len, /*is_retransmit*/ true, r->cb);
}

/* ---- send gating + deferred flush (caller must hold conn->lock) ---- */

typedef struct {
    nl_connection_t *conn;
    uint8_t channel;
    nl_delivery_t delivery;
    const uint8_t *data;
    size_t len;
    uint64_t now_ms;
    const nl_conn_callbacks_t *cb;
} send_attempt_t;

static bool is_reliable_mode(nl_delivery_t d) {
    return d == NL_RELIABLE_UNORDERED || d == NL_RELIABLE_ORDERED;
}

/* May this payload leave now? Congestion window gates reliable only (no
 * ack clock for unreliable); peer rwnd gates both. Does NOT consume rate
 * tokens -- call rate_consume only once emit is actually committed, so a
 * failed window check never steals budget. */
static bool send_window_open(nl_connection_t *conn, const send_attempt_t *a) {
    if (is_reliable_mode(a->delivery) && reliable_in_flight(conn) >= conn->cwnd) {
        return false;
    }
    if ((uint32_t)a->len > (uint32_t)conn->peer_rwnd) return false;
    if (conn->rate_bps != 0) {
        rate_refill(conn, a->now_ms);
        if (conn->rate_tokens < (double)a->len) return false;
    }
    return true;
}

static void rate_consume(nl_connection_t *conn, size_t bytes) {
    if (conn->rate_bps != 0) conn->rate_tokens -= (double)bytes;
}

static nl_result_t do_channel_send(nl_connection_t *conn, const send_attempt_t *a) {
    rate_consume(conn, a->len);
    emit_ctx_t ectx = { conn, a->cb };
    uint16_t rwnd = nl_connection_adv_window(conn);
    nl_result_t r = nl_channel_send(&conn->channels[a->channel], a->now_ms, a->channel, a->delivery,
                                     a->data, a->len, rwnd, on_channel_emit, &ectx);
    if (r == NL_OK) conn->last_send_time_ms = a->now_ms;
    return r;
}

/* Called with the lock held after any event that may have opened budget
 * (acks, tick/refill, peer rwnd update). Only the head is tried so
 * priority order is never violated by a lower-priority tail sneaking past
 * a blocked head. */
static void flush_deferred(nl_connection_t *conn, uint64_t now_ms, const nl_conn_callbacks_t *cb) {
    while (conn->deferred_head) {
        nl_deferred_msg_t *head = conn->deferred_head;
        send_attempt_t a = {
            .conn = conn,
            .channel = head->channel,
            .delivery = (nl_delivery_t)head->delivery,
            .data = head->data,
            .len = head->len,
            .now_ms = now_ms,
            .cb = cb,
        };
        if (!send_window_open(conn, &a)) break;
        rate_consume(conn, head->len);
        emit_ctx_t ectx = { conn, cb };
        uint16_t rwnd = nl_connection_adv_window(conn);
        nl_result_t r = nl_channel_send(&conn->channels[head->channel], now_ms, head->channel,
                                         (nl_delivery_t)head->delivery, head->data, head->len,
                                         rwnd, on_channel_emit, &ectx);
        if (r != NL_OK) break; /* channel-level reject: leave head parked */
        conn->last_send_time_ms = now_ms;
        deferred_pop(conn);
        free(head->data);
        free(head);
    }
}

nl_result_t nl_connection_send(nl_connection_t *conn, uint8_t channel, nl_delivery_t delivery,
                                const uint8_t *data, size_t len, uint8_t priority,
                                uint64_t now_ms, const nl_conn_callbacks_t *cb) {
    if (channel >= conn->channel_count) return NL_ERR_CHANNEL_OUT_OF_RANGE;
    if ((int)delivery < 0 || (int)delivery >= NL_LANES_PER_CHANNEL) return NL_ERR_INVALID_ARGUMENT;
    if (len > 0 && !data) return NL_ERR_INVALID_ARGUMENT;
    if (len > NL_MAX_MESSAGE_SIZE) return NL_ERR_MESSAGE_TOO_LARGE;

    pthread_mutex_lock(&conn->lock);
    if (conn->state != NL_CONN_CONNECTED) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_NOT_CONNECTED;
    }

    send_attempt_t a = {
        .conn = conn, .channel = channel, .delivery = delivery,
        .data = data, .len = len, .now_ms = now_ms, .cb = cb,
    };

    /* Anything already parked must go out first: always enqueue behind it
     * so priority/FIFO order is never violated by a later immediate send. */
    if (conn->deferred_head != NULL) {
        if (!deferred_push(conn, channel, delivery, priority, data, len)) {
            pthread_mutex_unlock(&conn->lock);
            return NL_ERR_QUEUE_FULL;
        }
        flush_deferred(conn, now_ms, cb);
        pthread_mutex_unlock(&conn->lock);
        return NL_OK;
    }

    if (send_window_open(conn, &a)) {
        nl_result_t r = do_channel_send(conn, &a);
        if (r == NL_OK) {
            pthread_mutex_unlock(&conn->lock);
            return NL_OK;
        }
        /* Permanent channel-level failure (bad size etc.) -- do not defer. */
        pthread_mutex_unlock(&conn->lock);
        return r;
    }

    /* Window/rate closed: park until budget opens (tick/ack/rwnd update). */
    if (!deferred_push(conn, channel, delivery, priority, data, len)) {
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_QUEUE_FULL;
    }
    pthread_mutex_unlock(&conn->lock);
    return NL_OK;
}

typedef struct {
    nl_peer_id_t peer;
    const nl_conn_callbacks_t *cb;
    nl_connection_t *conn;
} deliver_ctx_t;

static void on_channel_deliver(void *ctx, uint8_t channel_id, nl_delivery_t delivery,
                                const uint8_t *data, uint32_t len) {
    deliver_ctx_t *d = (deliver_ctx_t *)ctx;
    d->cb->on_data(d->cb->ctx, d->peer, channel_id, delivery, data, len);
    /* Flow control: bytes handed to the event queue occupy local window
     * until nl_poll_event returns them to the app (nl_connection_consume_window).
     * Called from on_packet with conn->lock already held. */
    nl_connection_t *conn = d->conn;
    if (conn->recv_window_size > conn->recv_window_used) {
        uint32_t room = conn->recv_window_size - conn->recv_window_used;
        conn->recv_window_used += (len < room ? len : room);
    }
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
        conn->stats.duplicates_received++;
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
        conn->stats.duplicates_received++;
        pthread_mutex_unlock(&conn->lock);
        return NL_ERR_PROTOCOL_MISMATCH; /* lost a race with another thread's identical packet */
    }

    conn->last_recv_time_ms = now_ms;
    conn->stats.packets_received++;
    conn->stats.bytes_received += enc_body_len + 1; /* +1 for the type byte, passed separately */

    nl_result_t result = NL_OK;
    bool just_confirmed = false;
    bool became_disconnected = false;
    uint32_t total_newly_acked = 0;
    bool fast_loss = false;
    uint64_t retx_before = conn->stats.retransmits;

    switch (type) {
        case NL_PKT_DATA: {
            deliver_ctx_t dctx = { conn->id, cb, conn };
            /* Route by the channel_id embedded in the plaintext (byte 0
             * of the DATA payload) into that channel's state. */
            if (ct_len < 1) { result = NL_ERR_PROTOCOL_MISMATCH; break; }
            uint8_t channel_id = plaintext[0];
            if (channel_id >= conn->channel_count) { result = NL_ERR_CHANNEL_OUT_OF_RANGE; break; }
            retransmit_ctx_t rctx = { conn, cb };
            bool has_rtt_sample = false;
            uint32_t rtt_sample_ms = 0;
            uint32_t newly_acked = 0;
            uint16_t peer_rwnd = conn->peer_rwnd;
            uint16_t adv = nl_connection_adv_window(conn);

            nl_channel_on_receive(&conn->channels[channel_id], now_ms, plaintext, (uint16_t)ct_len,
                                   adv, on_channel_deliver, &dctx,
                                   on_channel_retransmit, &rctx,
                                   &has_rtt_sample, &rtt_sample_ms,
                                   &newly_acked, &peer_rwnd);
            conn->peer_rwnd = peer_rwnd;
            total_newly_acked += newly_acked;
            if (has_rtt_sample) update_rtt(conn, rtt_sample_ms);
            if (conn->stats.retransmits > retx_before) fast_loss = true;
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
            became_disconnected = true;
            break;
        default:
            result = NL_ERR_PROTOCOL_MISMATCH;
            break;
    }

    if (total_newly_acked > 0) cc_on_acks(conn, total_newly_acked);
    if (fast_loss) cc_on_loss(conn, /*fast*/ true);

    /* Acks (and the peer's new rwnd) open budget for deferred sends. */
    if (conn->deferred_head) flush_deferred(conn, now_ms, cb);

    pthread_mutex_unlock(&conn->lock);

    if (just_confirmed && cb->on_connected) {
        cb->on_connected(cb->ctx, conn->id);
    }
    if (became_disconnected) {
        cb->on_disconnected(cb->ctx, conn->id, NL_OK); /* peer-initiated graceful close */
    }

    return result;
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

    /* Server-side CONNECT_ACCEPTED retransmission: the client only becomes
     * "connected" once it decrypts one of these, so a single lost datagram
     * would otherwise stall the handshake until the idle timeout. Only the
     * server side ever arms this (is_client_side connections never send
     * ACCEPTED); budget is finite so a vanished client can't pin us forever.
     * Re-arming stops once the client has sent anything back that we could
     * authenticate -- receiving a valid packet proves the handshake keys
     * round-tripped, so further ACCEPTED retries are pointless. */
    if (!conn->is_client_side && conn->accept_retries_left > 0 &&
        conn->last_recv_time_ms <= conn->accept_sent_ms) {
        if (now_ms - conn->accept_sent_ms >= NL_HANDSHAKE_RETRY_MS) {
            uint8_t empty[1] = {0};
            encrypt_and_emit(conn, NL_PKT_CONNECT_ACCEPTED, empty, 0, /*is_retransmit*/ false, cb);
            conn->accept_sent_ms = now_ms;
            conn->accept_retries_left--;
        }
    }

    /* Retransmission scan across every channel's reliable lanes. */
    retransmit_ctx_t rctx = { conn, cb };
    bool any_gave_up = false;
    uint64_t retx_before = conn->stats.retransmits;
    uint16_t adv = nl_connection_adv_window(conn);
    for (uint8_t c = 0; c < conn->channel_count; c++) {
        bool give_up = false;
        nl_channel_tick(&conn->channels[c], c, now_ms, conn->rto_ms, NL_MAX_RETRIES, adv,
                         on_channel_retransmit, &rctx, &give_up);
        any_gave_up = any_gave_up || give_up;
    }
    if (conn->stats.retransmits > retx_before) cc_on_loss(conn, /*fast*/ false);

    /* Rate tokens refill with wall time; re-check deferred queue. */
    if (conn->deferred_head) {
        rate_refill(conn, now_ms);
        flush_deferred(conn, now_ms, cb);
    }

    /* Idle keepalive so a channel with no application traffic still gets
     * timely acks and RTT samples, and the peer's idle timer keeps resetting. */
    if (now_ms - conn->last_send_time_ms >= conn->keepalive_interval_ms) {
        uint8_t empty[1] = {0};
        encrypt_and_emit(conn, NL_PKT_KEEPALIVE, empty, 0, /*is_retransmit*/ false, cb);
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
        encrypt_and_emit(conn, NL_PKT_DISCONNECT, empty, 0, /*is_retransmit*/ false, cb);
        conn->state = NL_CONN_DISCONNECTED;
        conn->last_send_time_ms = now_ms;
    }
    pthread_mutex_unlock(&conn->lock);
}

void nl_connection_send_handshake_complete(nl_connection_t *conn, uint64_t now_ms,
                                            bool is_retry, const nl_conn_callbacks_t *cb) {
    pthread_mutex_lock(&conn->lock);
    uint8_t empty[1] = {0};
    encrypt_and_emit(conn, NL_PKT_CONNECT_ACCEPTED, empty, 0, /*is_retransmit*/ false, cb);
    if (is_retry) {
        /* Tick-driven resend: refresh the timer, leave the remaining budget
         * alone (it was armed by the initial send). */
        conn->accept_sent_ms = now_ms;
    } else {
        /* Initial send arms the retransmission budget. */
        conn->accept_sent_ms = now_ms;
        conn->accept_retries_left = NL_ACCEPT_RETRIES;
    }
    pthread_mutex_unlock(&conn->lock);
}

uint32_t nl_connection_rtt_ms(nl_connection_t *conn) {
    pthread_mutex_lock(&conn->lock);
    uint32_t rtt = conn->rtt_ms;
    pthread_mutex_unlock(&conn->lock);
    return rtt;
}

void nl_connection_get_stats(nl_connection_t *conn, nl_connection_stats_t *out) {
    pthread_mutex_lock(&conn->lock);
    *out = conn->stats;
    out->rtt_ms = conn->rtt_ms;
    out->rtt_var_ms = (uint32_t)conn->rttvar_ms;
    out->rto_ms = conn->rto_ms;
    pthread_mutex_unlock(&conn->lock);
}

uint32_t nl_connection_capabilities(nl_connection_t *conn) {
    pthread_mutex_lock(&conn->lock);
    uint32_t caps = conn->capabilities;
    pthread_mutex_unlock(&conn->lock);
    return caps;
}

uint16_t nl_connection_adv_window(nl_connection_t *conn) {
    /* Assumes conn->lock is held (or the connection is not yet published):
     * every mutator of recv_window_used runs under that lock. */
    if (conn->recv_window_used >= conn->recv_window_size) return 0;
    uint32_t avail = conn->recv_window_size - conn->recv_window_used;
    if (avail > NL_RECV_WINDOW_MAX) avail = NL_RECV_WINDOW_MAX;
    return (uint16_t)avail;
}

void nl_connection_consume_window(nl_connection_t *conn, uint32_t bytes) {
    if (!conn) return;
    pthread_mutex_lock(&conn->lock);
    if (bytes >= conn->recv_window_used) conn->recv_window_used = 0;
    else conn->recv_window_used -= bytes;
    pthread_mutex_unlock(&conn->lock);
    /* Window just opened: a deferred send may fit now. We cannot flush
     * here without the callbacks (and must not take the endpoint lock from
     * poll's queue section); the next tick (<=50ms) or inbound packet
     * flushes. Tests that need immediate flush call the connection tick. */
}
