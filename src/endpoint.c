/* Needed for clock_gettime, getaddrinfo, and other POSIX.1-2008 APIs when
 * building with a strict -std=c11 (rather than gnu11): glibc hides them
 * behind this feature-test macro otherwise. Must come before any system
 * header is included. */
#define _POSIX_C_SOURCE 200809L

/* endpoint.c - the public API surface: sockets, background I/O thread,
 * connect handshake state machine, connection table, and event queue.
 *
 * Locking discipline (read this before touching connection/pending
 * tables):
 *   - `connections_lock` guards the connections[] array AND is held for
 *     the full duration of any nl_connection_* call made through it. This
 *     is coarser than strictly necessary (two unrelated connections can't
 *     send concurrently) but it is what makes connection lifetime safe
 *     without reference counting: a connection is only ever freed while
 *     this lock is held, and it is only ever looked up while this lock is
 *     held, so there is no window for another thread to be holding a
 *     stale pointer when it's freed. A sharded lock (e.g. per-bucket in a
 *     real hash table) would remove this bottleneck; see README roadmap.
 *   - `pending_lock` guards the in-progress-handshake table, independent
 *     of `connections_lock`.
 *   - `queue_lock` (+ `queue_cond`) guards the event queue.
 *   - Callbacks invoked *while* connections_lock is already held (i.e.
 *     from inside a call chain that started under it) must NOT attempt to
 *     take connections_lock again -- see ep_on_disconnected/ep_on_connected.
 */
#include "../include/netlink.h"
#include "connection.h"
#include "protocol.h"
#include "crypto.h"
#include "byteorder.h"
#include "socket_compat.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>

#define NL_MAX_CONNECTIONS_INTERNAL 512
#define NL_MAX_PENDING 128
#define NL_PENDING_TIMEOUT_MS 5000
#define NL_RECV_BUFFER_SIZE 2048
#define NL_RATE_LIMIT_WINDOW_MS 1000
#define NL_RATE_LIMIT_MAX_PER_WINDOW 200
#define NL_IO_POLL_INTERVAL_MS 50

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ---- address helpers ---- */

/* Normalized (family, port, raw address bytes) encoding used anywhere we
 * need deterministic bytes derived from a socket address (cookie HMACs).
 * We deliberately do NOT hash the raw struct sockaddr_storage: it can
 * contain uninitialized padding that differs between two calls to
 * recvfrom() for packets from the same logical address, which would make
 * cookie verification fail unpredictably. */
static size_t normalize_addr_bytes(const struct sockaddr_storage *addr, uint8_t out[19]) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        out[0] = 4;
        nl_put_u16(out + 1, ntohs(a->sin_port));
        memcpy(out + 3, &a->sin_addr, 4);
        return 7;
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        out[0] = 6;
        nl_put_u16(out + 1, ntohs(a->sin6_port));
        memcpy(out + 3, &a->sin6_addr, 16);
        return 19;
    }
    out[0] = 0;
    return 1;
}

static bool addr_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    uint8_t na[19], nb[19];
    size_t la = normalize_addr_bytes(a, na);
    size_t lb = normalize_addr_bytes(b, nb);
    return la == lb && memcmp(na, nb, la) == 0;
}

static void sockaddr_to_nl_address(const struct sockaddr_storage *addr, socklen_t addr_len, nl_address_t *out) {
    (void)addr_len;
    memset(out, 0, sizeof(*out));
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &a->sin_addr, out->host, sizeof(out->host));
        out->port = ntohs(a->sin_port);
        out->family = NL_AF_INET;
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &a->sin6_addr, out->host, sizeof(out->host));
        out->port = ntohs(a->sin6_port);
        out->family = NL_AF_INET6;
    }
}

static bool resolve_address(const nl_address_t *addr, bool passive, struct sockaddr_storage *out,
                             socklen_t *out_len, int *out_family) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = (addr->family == NL_AF_INET) ? AF_INET
                     : (addr->family == NL_AF_INET6) ? AF_INET6
                     : AF_UNSPEC;
    if (passive) hints.ai_flags = AI_PASSIVE;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", addr->port);

    const char *host = addr->host[0] ? addr->host : (passive ? NULL : "127.0.0.1");

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res) return false;

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    *out_family = res->ai_family;
    freeaddrinfo(res);
    return true;
}

/* ---- pending handshake table ---- */

typedef enum {
    PENDING_SERVER_AWAIT_RESPONSE,
    PENDING_CLIENT_AWAIT_CHALLENGE,
    PENDING_CLIENT_AWAIT_ACCEPTED,
} pending_role_t;

typedef struct {
    bool in_use;
    pending_role_t role;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    nl_keypair_t *my_keypair;
    uint8_t my_nonce[16];
    uint8_t peer_pubkey[32];
    uint8_t peer_nonce[16];
    uint8_t cookie[16];
    uint64_t connection_id;
    uint8_t channel_count;
    uint64_t created_ms;
} pending_t;

/* ---- event queue ---- */

typedef struct event_node {
    nl_event_t pub;
    uint8_t *payload;
    uint32_t payload_len;
    struct event_node *next;
} event_node_t;

struct nl_endpoint {
    bool is_server;
    nl_config_t config;
    nl_socket_t sock;

    uint8_t server_secret[32]; /* server role only: HMAC key for connect cookies */

    pending_t pending[NL_MAX_PENDING];
    pthread_mutex_t pending_lock;

    nl_connection_t *connections[NL_MAX_CONNECTIONS_INTERNAL];
    pthread_mutex_t connections_lock;

    event_node_t *queue_head, *queue_tail;
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_cond;
    uint8_t *returned_owned_data;

    pthread_t io_thread;
    volatile bool running;

    nl_socket_t discovery_sock;
    uint16_t discovery_port;
    uint32_t discovery_probe_nonce;

    uint64_t rate_window_start_ms;
    uint32_t rate_count;
};

typedef struct {
    nl_endpoint_t *ep;
    nl_connection_t *conn;
} conn_ctx_t;

/* ---- event queue push/pop ---- */

static void push_event(nl_endpoint_t *ep, nl_event_t ev, const uint8_t *data, uint32_t len) {
    event_node_t *node = (event_node_t *)calloc(1, sizeof(event_node_t));
    if (!node) return; /* OOM: drop the event rather than crash */
    node->pub = ev;
    node->pub.data = NULL;
    node->pub.data_len = 0;
    if (len > 0 && data) {
        node->payload = (uint8_t *)malloc(len);
        if (!node->payload) { free(node); return; }
        memcpy(node->payload, data, len);
        node->payload_len = len;
    }
    pthread_mutex_lock(&ep->queue_lock);
    node->next = NULL;
    if (ep->queue_tail) ep->queue_tail->next = node; else ep->queue_head = node;
    ep->queue_tail = node;
    pthread_cond_signal(&ep->queue_cond);
    pthread_mutex_unlock(&ep->queue_lock);
}

/* ---- connection table helpers (caller must hold connections_lock) ---- */

static nl_connection_t *find_connection_locked(nl_endpoint_t *ep, nl_peer_id_t id) {
    for (int i = 0; i < NL_MAX_CONNECTIONS_INTERNAL; i++) {
        if (ep->connections[i] && ep->connections[i]->id == id) return ep->connections[i];
    }
    return NULL;
}

static int find_free_connection_slot_locked(nl_endpoint_t *ep) {
    for (int i = 0; i < NL_MAX_CONNECTIONS_INTERNAL; i++) {
        if (!ep->connections[i]) return i;
    }
    return -1;
}

static int find_connection_slot_by_ptr_locked(nl_endpoint_t *ep, nl_connection_t *conn) {
    for (int i = 0; i < NL_MAX_CONNECTIONS_INTERNAL; i++) {
        if (ep->connections[i] == conn) return i;
    }
    return -1;
}

static uint32_t count_active_connections_locked(nl_endpoint_t *ep) {
    uint32_t n = 0;
    for (int i = 0; i < NL_MAX_CONNECTIONS_INTERNAL; i++) if (ep->connections[i]) n++;
    return n;
}

/* ---- connection.c callback glue ---- */

static void ep_send_wire(void *ctx, nl_peer_id_t peer, const uint8_t *packet, size_t len) {
    (void)peer;
    conn_ctx_t *c = (conn_ctx_t *)ctx;
    sendto(c->ep->sock, packet, len, 0, (struct sockaddr *)&c->conn->addr, c->conn->addr_len);
}

static void ep_on_data(void *ctx, nl_peer_id_t peer, uint8_t channel, nl_delivery_t delivery,
                        const uint8_t *data, uint32_t len) {
    (void)delivery;
    conn_ctx_t *c = (conn_ctx_t *)ctx;
    nl_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = NL_EVENT_DATA;
    ev.peer = peer;
    ev.channel = channel;
    push_event(c->ep, ev, data, len);
}

/* Called while connections_lock is ALREADY held (see file header). Must
 * not attempt to lock it again. */
static void ep_on_disconnected(void *ctx, nl_peer_id_t peer, nl_result_t reason) {
    conn_ctx_t *c = (conn_ctx_t *)ctx;
    bool never_confirmed = c->conn->is_client_side && !c->conn->handshake_confirmed;

    int slot = find_connection_slot_by_ptr_locked(c->ep, c->conn);
    if (slot >= 0) c->ep->connections[slot] = NULL;
    nl_connection_destroy(c->conn);

    nl_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = never_confirmed ? NL_EVENT_CONNECT_FAILED : NL_EVENT_DISCONNECTED;
    ev.peer = peer;
    ev.disconnect_reason = reason;
    push_event(c->ep, ev, NULL, 0);
}

static void ep_on_connected(void *ctx, nl_peer_id_t peer) {
    conn_ctx_t *c = (conn_ctx_t *)ctx;
    nl_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = NL_EVENT_CONNECTED;
    ev.peer = peer;
    sockaddr_to_nl_address(&c->conn->addr, c->conn->addr_len, &ev.from_address);
    push_event(c->ep, ev, NULL, 0);
}

static nl_conn_callbacks_t make_callbacks(conn_ctx_t *cctx) {
    nl_conn_callbacks_t cb;
    cb.on_data = ep_on_data;
    cb.on_disconnected = ep_on_disconnected;
    cb.send_wire = ep_send_wire;
    cb.on_connected = ep_on_connected;
    cb.ctx = cctx;
    return cb;
}

/* ---- pending table helpers ---- */

static void release_pending_locked(pending_t *p) {
    if (p->my_keypair) { nl_keypair_free(p->my_keypair); p->my_keypair = NULL; }
    memset(p, 0, sizeof(*p));
}

static pending_t *acquire_pending_slot_locked(nl_endpoint_t *ep, uint64_t now) {
    for (int i = 0; i < NL_MAX_PENDING; i++) {
        if (!ep->pending[i].in_use) return &ep->pending[i];
    }
    /* Table full: evict the oldest rather than reject outright, bounding
     * memory/state under a handshake flood while staying available. */
    int oldest = 0;
    for (int i = 1; i < NL_MAX_PENDING; i++) {
        if (ep->pending[i].created_ms < ep->pending[oldest].created_ms) oldest = i;
    }
    release_pending_locked(&ep->pending[oldest]);
    (void)now;
    return &ep->pending[oldest];
}

static pending_t *find_pending_by_addr_locked(nl_endpoint_t *ep, const struct sockaddr_storage *addr,
                                               pending_role_t role) {
    for (int i = 0; i < NL_MAX_PENDING; i++) {
        if (ep->pending[i].in_use && ep->pending[i].role == role && addr_equal(&ep->pending[i].addr, addr)) {
            return &ep->pending[i];
        }
    }
    return NULL;
}

static void expire_pending(nl_endpoint_t *ep, uint64_t now) {
    pthread_mutex_lock(&ep->pending_lock);
    for (int i = 0; i < NL_MAX_PENDING; i++) {
        if (ep->pending[i].in_use && (now - ep->pending[i].created_ms) > NL_PENDING_TIMEOUT_MS) {
            pending_role_t role = ep->pending[i].role;
            uint64_t connid = ep->pending[i].connection_id;
            release_pending_locked(&ep->pending[i]);
            if (role == PENDING_CLIENT_AWAIT_CHALLENGE || role == PENDING_CLIENT_AWAIT_ACCEPTED) {
                nl_event_t ev; memset(&ev, 0, sizeof(ev));
                ev.type = NL_EVENT_CONNECT_FAILED;
                ev.peer = connid;
                ev.disconnect_reason = NL_ERR_TIMEOUT;
                push_event(ep, ev, NULL, 0);
            }
        }
    }
    pthread_mutex_unlock(&ep->pending_lock);
}

static bool rate_limit_check(nl_endpoint_t *ep, uint64_t now) {
    /* Simple fixed-window counter -- bounds how much handshake-processing
     * CPU an attacker can force us to spend per second. Not as smooth as
     * a token bucket, but a great deal simpler and sufficient to blunt a
     * flood without adding real complexity. */
    if (now - ep->rate_window_start_ms > NL_RATE_LIMIT_WINDOW_MS) {
        ep->rate_window_start_ms = now;
        ep->rate_count = 0;
    }
    ep->rate_count++;
    return ep->rate_count <= NL_RATE_LIMIT_MAX_PER_WINDOW;
}

static nl_result_t deny_reason_to_result(uint8_t reason) {
    switch (reason) {
        case NL_DENY_SERVER_FULL: return NL_ERR_SERVER_FULL;
        case NL_DENY_PROTOCOL_MISMATCH: return NL_ERR_PROTOCOL_MISMATCH;
        default: return NL_ERR_DENIED;
    }
}

static void send_denied(nl_endpoint_t *ep, const struct sockaddr_storage *addr, socklen_t addr_len, uint8_t reason) {
    uint8_t out[NL_CONNECT_DENIED_SIZE];
    out[0] = NL_PKT_CONNECT_DENIED;
    out[1] = reason;
    sendto(ep->sock, out, sizeof(out), 0, (const struct sockaddr *)addr, addr_len);
}

/* ---- HKDF-derived session key/salt bundle ---- */

typedef struct {
    uint8_t c2s_key[32], s2c_key[32];
    uint8_t c2s_salt[12], s2c_salt[12];
} session_keys_t;

static bool derive_session_keys(const uint8_t shared[32], const uint8_t client_nonce[16],
                                 const uint8_t server_nonce[16], session_keys_t *out) {
    uint8_t salt[32];
    memcpy(salt, client_nonce, 16);
    memcpy(salt + 16, server_nonce, 16);
    bool ok = true;
    ok &= nl_crypto_hkdf_sha256(shared, 32, salt, 32, (const uint8_t *)"netlink v1 c2s key", 18, out->c2s_key, 32);
    ok &= nl_crypto_hkdf_sha256(shared, 32, salt, 32, (const uint8_t *)"netlink v1 s2c key", 18, out->s2c_key, 32);
    ok &= nl_crypto_hkdf_sha256(shared, 32, salt, 32, (const uint8_t *)"netlink v1 c2s salt", 19, out->c2s_salt, 12);
    ok &= nl_crypto_hkdf_sha256(shared, 32, salt, 32, (const uint8_t *)"netlink v1 s2c salt", 19, out->s2c_salt, 12);
    return ok;
}

/* ---- handshake: server side ---- */

static void handle_connect_request(nl_endpoint_t *ep, const uint8_t *buf, size_t len,
                                    const struct sockaddr_storage *from, socklen_t from_len, uint64_t now) {
    if (len < NL_CONNECT_REQUEST_SIZE) return;
    size_t off = 1;
    uint32_t magic = nl_get_u32(buf + off); off += 4;
    uint16_t version = nl_get_u16(buf + off); off += 2;
    uint8_t req_channels = buf[off]; off += 1;
    uint64_t client_connid = nl_get_u64(buf + off); off += 8;
    uint8_t client_pub[32]; memcpy(client_pub, buf + off, 32); off += 32;
    uint8_t client_nonce[16]; memcpy(client_nonce, buf + off, 16); off += 16;

    if (magic != NL_MAGIC || version != NL_PROTOCOL_VERSION) {
        send_denied(ep, from, from_len, NL_DENY_PROTOCOL_MISMATCH);
        return;
    }
    if (!rate_limit_check(ep, now)) return; /* silently drop under flood, don't amplify */

    pthread_mutex_lock(&ep->connections_lock);
    uint32_t active = count_active_connections_locked(ep);
    pthread_mutex_unlock(&ep->connections_lock);
    uint32_t max_conn = ep->config.max_connections ? ep->config.max_connections : 64;
    if (active >= max_conn) {
        send_denied(ep, from, from_len, NL_DENY_SERVER_FULL);
        return;
    }

    uint8_t channel_count = req_channels;
    if (channel_count == 0 || channel_count > NL_MAX_CHANNELS) {
        channel_count = ep->config.channel_count ? ep->config.channel_count : 4;
    }

    pthread_mutex_lock(&ep->pending_lock);
    pending_t *p = acquire_pending_slot_locked(ep, now);
    p->my_keypair = nl_keypair_generate();
    if (!p->my_keypair) { memset(p, 0, sizeof(*p)); pthread_mutex_unlock(&ep->pending_lock); return; }
    p->in_use = true;
    p->role = PENDING_SERVER_AWAIT_RESPONSE;
    memcpy(&p->addr, from, sizeof(*from));
    p->addr_len = from_len;
    nl_crypto_random(p->my_nonce, 16);
    memcpy(p->peer_pubkey, client_pub, 32);
    memcpy(p->peer_nonce, client_nonce, 16);
    p->connection_id = client_connid;
    p->channel_count = channel_count;
    p->created_ms = now;

    uint8_t addr_bytes[19];
    size_t addr_bytes_len = normalize_addr_bytes(from, addr_bytes);
    uint8_t cookie_input[19 + 32 + 16 + 16];
    size_t ci = 0;
    memcpy(cookie_input + ci, addr_bytes, addr_bytes_len); ci += addr_bytes_len;
    memcpy(cookie_input + ci, client_pub, 32); ci += 32;
    memcpy(cookie_input + ci, client_nonce, 16); ci += 16;
    memcpy(cookie_input + ci, p->my_nonce, 16); ci += 16;
    nl_crypto_hmac_sha256(ep->server_secret, 32, cookie_input, ci, p->cookie, 16);

    uint8_t server_pub[32];
    nl_keypair_public(p->my_keypair, server_pub);
    uint8_t server_nonce_copy[16]; memcpy(server_nonce_copy, p->my_nonce, 16);
    uint8_t cookie_copy[16]; memcpy(cookie_copy, p->cookie, 16);
    pthread_mutex_unlock(&ep->pending_lock);

    uint8_t out[NL_CONNECT_CHALLENGE_SIZE];
    size_t o = 0;
    out[o++] = NL_PKT_CONNECT_CHALLENGE;
    memcpy(out + o, server_pub, 32); o += 32;
    memcpy(out + o, server_nonce_copy, 16); o += 16;
    memcpy(out + o, cookie_copy, 16); o += 16;
    sendto(ep->sock, out, o, 0, (const struct sockaddr *)from, from_len);
}

static void handle_connect_response(nl_endpoint_t *ep, const uint8_t *buf, size_t len,
                                     const struct sockaddr_storage *from, socklen_t from_len, uint64_t now) {
    (void)from_len; /* the pending entry's own stored addr_len is used instead, see below */
    if (len < NL_CONNECT_RESPONSE_SIZE) return;
    size_t off = 1;
    uint8_t cookie[16]; memcpy(cookie, buf + off, 16); off += 16;
    uint8_t client_pub[32]; memcpy(client_pub, buf + off, 32); off += 32;
    uint8_t client_nonce[16]; memcpy(client_nonce, buf + off, 16); off += 16;

    pthread_mutex_lock(&ep->pending_lock);
    pending_t *p = find_pending_by_addr_locked(ep, from, PENDING_SERVER_AWAIT_RESPONSE);
    if (!p || !nl_crypto_const_time_eq(cookie, p->cookie, 16) ||
        memcmp(client_pub, p->peer_pubkey, 32) != 0 || memcmp(client_nonce, p->peer_nonce, 16) != 0) {
        pthread_mutex_unlock(&ep->pending_lock);
        return; /* invalid/spoofed/stale response, drop silently */
    }

    uint8_t shared[32];
    bool ok = nl_crypto_x25519(p->my_keypair, p->peer_pubkey, shared);
    session_keys_t keys;
    if (ok) ok = derive_session_keys(shared, p->peer_nonce /*client nonce*/, p->my_nonce /*server nonce*/, &keys);
    memset(shared, 0, sizeof(shared));
    if (!ok) { release_pending_locked(p); pthread_mutex_unlock(&ep->pending_lock); return; }

    uint64_t connid = p->connection_id;
    uint8_t channel_count = p->channel_count;
    struct sockaddr_storage paddr = p->addr;
    socklen_t paddr_len = p->addr_len;
    release_pending_locked(p);
    pthread_mutex_unlock(&ep->pending_lock);

    pthread_mutex_lock(&ep->connections_lock);
    if (find_connection_locked(ep, connid)) {
        pthread_mutex_unlock(&ep->connections_lock); /* astronomically-unlikely id collision: reject */
        memset(&keys, 0, sizeof(keys));
        return;
    }
    nl_connection_t *conn = nl_connection_create(connid, &paddr, paddr_len, false, channel_count,
                                                  keys.s2c_key, keys.c2s_key, keys.s2c_salt, keys.c2s_salt,
                                                  ep->config.connection_timeout_ms, ep->config.keepalive_interval_ms,
                                                  now);
    memset(&keys, 0, sizeof(keys));
    if (!conn) { pthread_mutex_unlock(&ep->connections_lock); return; }
    int slot = find_free_connection_slot_locked(ep);
    if (slot < 0) { nl_connection_destroy(conn); pthread_mutex_unlock(&ep->connections_lock); return; }
    ep->connections[slot] = conn;

    conn_ctx_t cctx = { ep, conn };
    nl_conn_callbacks_t cb = make_callbacks(&cctx);
    nl_connection_send_handshake_complete(conn, &cb);

    nl_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = NL_EVENT_CONNECTED;
    ev.peer = connid;
    sockaddr_to_nl_address(&paddr, paddr_len, &ev.from_address);
    push_event(ep, ev, NULL, 0);

    pthread_mutex_unlock(&ep->connections_lock);
}

/* ---- handshake: client side ---- */

static void handle_connect_challenge(nl_endpoint_t *ep, const uint8_t *buf, size_t len,
                                      const struct sockaddr_storage *from, socklen_t from_len, uint64_t now) {
    if (len < NL_CONNECT_CHALLENGE_SIZE) return;
    size_t off = 1;
    uint8_t server_pub[32]; memcpy(server_pub, buf + off, 32); off += 32;
    uint8_t server_nonce[16]; memcpy(server_nonce, buf + off, 16); off += 16;
    uint8_t cookie[16]; memcpy(cookie, buf + off, 16); off += 16;

    pthread_mutex_lock(&ep->pending_lock);
    pending_t *p = find_pending_by_addr_locked(ep, from, PENDING_CLIENT_AWAIT_CHALLENGE);
    if (!p) { pthread_mutex_unlock(&ep->pending_lock); return; /* not expecting this, or already handled */ }

    uint8_t shared[32];
    bool ok = nl_crypto_x25519(p->my_keypair, server_pub, shared);
    session_keys_t keys;
    if (ok) ok = derive_session_keys(shared, p->my_nonce /*client nonce*/, server_nonce, &keys);
    memset(shared, 0, sizeof(shared));
    if (!ok) { release_pending_locked(p); pthread_mutex_unlock(&ep->pending_lock); return; }

    uint64_t connid = p->connection_id;
    uint8_t channel_count = p->channel_count;
    uint8_t client_pub[32]; nl_keypair_public(p->my_keypair, client_pub);
    uint8_t client_nonce_copy[16]; memcpy(client_nonce_copy, p->my_nonce, 16);

    release_pending_locked(p); /* client needs no further pending state once keys are derived */
    pthread_mutex_unlock(&ep->pending_lock);

    pthread_mutex_lock(&ep->connections_lock);
    if (!find_connection_locked(ep, connid)) {
        nl_connection_t *conn = nl_connection_create(connid, from, from_len, true, channel_count,
                                                       keys.c2s_key, keys.s2c_key, keys.c2s_salt, keys.s2c_salt,
                                                       ep->config.connection_timeout_ms,
                                                       ep->config.keepalive_interval_ms, now);
        if (conn) {
            int slot = find_free_connection_slot_locked(ep);
            if (slot >= 0) ep->connections[slot] = conn; else nl_connection_destroy(conn);
        }
    }
    pthread_mutex_unlock(&ep->connections_lock);
    memset(&keys, 0, sizeof(keys));

    uint8_t out[NL_CONNECT_RESPONSE_SIZE];
    size_t o = 0;
    out[o++] = NL_PKT_CONNECT_RESPONSE;
    memcpy(out + o, cookie, 16); o += 16;
    memcpy(out + o, client_pub, 32); o += 32;
    memcpy(out + o, client_nonce_copy, 16); o += 16;
    sendto(ep->sock, out, o, 0, (const struct sockaddr *)from, from_len);
}

static void handle_connect_denied(nl_endpoint_t *ep, const uint8_t *buf, size_t len,
                                   const struct sockaddr_storage *from) {
    if (len < NL_CONNECT_DENIED_SIZE) return;
    uint8_t reason = buf[1];

    pthread_mutex_lock(&ep->pending_lock);
    pending_t *p = find_pending_by_addr_locked(ep, from, PENDING_CLIENT_AWAIT_CHALLENGE);
    nl_peer_id_t connid = NL_INVALID_PEER;
    if (p) { connid = p->connection_id; release_pending_locked(p); }
    pthread_mutex_unlock(&ep->pending_lock);

    nl_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = NL_EVENT_CONNECT_FAILED;
    ev.peer = connid;
    ev.disconnect_reason = deny_reason_to_result(reason);
    push_event(ep, ev, NULL, 0);
}

/* ---- discovery ---- */

static void process_discovery_packet(nl_endpoint_t *ep, const uint8_t *buf, size_t len,
                                      const struct sockaddr_storage *from, socklen_t from_len) {
    if (len < 1) return;
    uint8_t type = buf[0];
    if (type == NL_PKT_DISCOVERY_REQUEST && ep->is_server) {
        if (len < NL_DISCOVERY_REQUEST_SIZE) return;
        uint32_t magic = nl_get_u32(buf + 1);
        if (magic != NL_MAGIC) return;
        uint32_t nonce = nl_get_u32(buf + 5);

        pthread_mutex_lock(&ep->connections_lock);
        uint32_t player_count = count_active_connections_locked(ep);
        pthread_mutex_unlock(&ep->connections_lock);

        const char *name = ep->config.server_name ? ep->config.server_name : "";
        size_t name_len = strlen(name);
        if (name_len > NL_SERVER_NAME_MAX - 1) name_len = NL_SERVER_NAME_MAX - 1;

        uint8_t out[NL_DISCOVERY_RESPONSE_MIN_SIZE + NL_SERVER_NAME_MAX];
        size_t o = 0;
        out[o++] = NL_PKT_DISCOVERY_RESPONSE;
        nl_put_u32(out + o, nonce); o += 4;
        struct sockaddr_storage local_addr; socklen_t local_len = sizeof(local_addr);
        uint16_t server_port = 0;
        if (getsockname(ep->sock, (struct sockaddr *)&local_addr, &local_len) == 0) {
            nl_address_t a; sockaddr_to_nl_address(&local_addr, local_len, &a);
            server_port = a.port;
        }
        nl_put_u16(out + o, server_port); o += 2;
        nl_put_u32(out + o, player_count); o += 4;
        nl_put_u32(out + o, ep->config.max_connections ? ep->config.max_connections : 64); o += 4;
        out[o++] = (uint8_t)name_len;
        memcpy(out + o, name, name_len); o += name_len;

        sendto(ep->discovery_sock, out, o, 0, (const struct sockaddr *)from, from_len);
    } else if (type == NL_PKT_DISCOVERY_RESPONSE && !ep->is_server) {
        if (len < NL_DISCOVERY_RESPONSE_MIN_SIZE) return;
        size_t off = 1;
        uint32_t nonce = nl_get_u32(buf + off); off += 4;
        (void)nonce;
        uint16_t server_port = nl_get_u16(buf + off); off += 2;
        uint32_t player_count = nl_get_u32(buf + off); off += 4;
        uint32_t max_players = nl_get_u32(buf + off); off += 4;
        uint8_t name_len = buf[off++];
        if (off + name_len > len) return;

        nl_event_t ev; memset(&ev, 0, sizeof(ev));
        ev.type = NL_EVENT_DISCOVERY_REPLY;
        sockaddr_to_nl_address(from, from_len, &ev.from_address);
        ev.from_address.port = server_port;
        ev.server_player_count = player_count;
        ev.server_max_players = max_players;
        size_t copy_len = name_len < NL_SERVER_NAME_MAX - 1 ? name_len : NL_SERVER_NAME_MAX - 1;
        memcpy(ev.server_name, buf + off, copy_len);
        ev.server_name[copy_len] = '\0';
        push_event(ep, ev, NULL, 0);
    }
}

/* ---- main packet dispatch ---- */

static void process_main_packet(nl_endpoint_t *ep, const uint8_t *buf, size_t len,
                                 const struct sockaddr_storage *from, socklen_t from_len, uint64_t now) {
    if (len < 1) return;
    uint8_t type = buf[0];
    switch (type) {
        case NL_PKT_CONNECT_REQUEST:
            if (ep->is_server) handle_connect_request(ep, buf, len, from, from_len, now);
            break;
        case NL_PKT_CONNECT_CHALLENGE:
            if (!ep->is_server) handle_connect_challenge(ep, buf, len, from, from_len, now);
            break;
        case NL_PKT_CONNECT_RESPONSE:
            if (ep->is_server) handle_connect_response(ep, buf, len, from, from_len, now);
            break;
        case NL_PKT_CONNECT_DENIED:
            if (!ep->is_server) handle_connect_denied(ep, buf, len, from);
            break;
        case NL_PKT_DATA:
        case NL_PKT_KEEPALIVE:
        case NL_PKT_DISCONNECT:
        case NL_PKT_CONNECT_ACCEPTED: {
            if (len < 1 + 8) return;
            uint64_t connid = nl_get_u64(buf + 1);
            pthread_mutex_lock(&ep->connections_lock);
            nl_connection_t *conn = find_connection_locked(ep, connid);
            if (conn) {
                conn_ctx_t cctx = { ep, conn };
                nl_conn_callbacks_t cb = make_callbacks(&cctx);
                nl_connection_on_packet(conn, type, buf + 1, len - 1, now, &cb);
            }
            pthread_mutex_unlock(&ep->connections_lock);
            break;
        }
        default:
            break; /* unknown type: ignore */
    }
}

static void tick_all_connections(nl_endpoint_t *ep, uint64_t now) {
    pthread_mutex_lock(&ep->connections_lock);
    for (int i = 0; i < NL_MAX_CONNECTIONS_INTERNAL; i++) {
        nl_connection_t *conn = ep->connections[i];
        if (!conn) continue;
        conn_ctx_t cctx = { ep, conn };
        nl_conn_callbacks_t cb = make_callbacks(&cctx);
        nl_connection_tick(conn, now, &cb);
        /* Note: if nl_connection_tick disconnected this connection, its
         * on_disconnected callback already nulled ep->connections[i] and
         * freed conn -- we must not touch `conn` again after this call. */
    }
    pthread_mutex_unlock(&ep->connections_lock);
}

/* ---- I/O thread ---- */

static void *io_thread_main(void *arg) {
    nl_endpoint_t *ep = (nl_endpoint_t *)arg;
    uint8_t buf[NL_RECV_BUFFER_SIZE];

    while (ep->running) {
        struct pollfd fds[2];
        int nfds = 0;
        int main_idx = nfds;
        fds[nfds].fd = ep->sock; fds[nfds].events = POLLIN; fds[nfds].revents = 0; nfds++;
        int disc_idx = -1;
        if (ep->discovery_sock != NL_INVALID_SOCKET) {
            disc_idx = nfds;
            fds[nfds].fd = ep->discovery_sock; fds[nfds].events = POLLIN; fds[nfds].revents = 0; nfds++;
        }

        int rc = poll(fds, (nfds_t)nfds, NL_IO_POLL_INTERVAL_MS);
        if (rc > 0) {
            if (fds[main_idx].revents & POLLIN) {
                struct sockaddr_storage from; socklen_t from_len = sizeof(from);
                memset(&from, 0, sizeof(from));
                ssize_t n = recvfrom(ep->sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
                if (n > 0) process_main_packet(ep, buf, (size_t)n, &from, from_len, now_ms());
            }
            if (disc_idx >= 0 && (fds[disc_idx].revents & POLLIN)) {
                struct sockaddr_storage from; socklen_t from_len = sizeof(from);
                memset(&from, 0, sizeof(from));
                ssize_t n = recvfrom(ep->discovery_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
                if (n > 0) process_discovery_packet(ep, buf, (size_t)n, &from, from_len);
            }
        }

        uint64_t now = now_ms();
        tick_all_connections(ep, now);
        expire_pending(ep, now);
    }
    return NULL;
}

/* ---- endpoint construction ---- */

static nl_endpoint_t *endpoint_alloc(bool is_server, const nl_config_t *cfg) {
    nl_endpoint_t *ep = (nl_endpoint_t *)calloc(1, sizeof(nl_endpoint_t));
    if (!ep) return NULL;
    ep->is_server = is_server;
    ep->config = *cfg;
    if (ep->config.channel_count == 0) ep->config.channel_count = 4;
    if (ep->config.channel_count > NL_MAX_CHANNELS) ep->config.channel_count = NL_MAX_CHANNELS;
    if (ep->config.max_connections == 0) ep->config.max_connections = 64;
    if (ep->config.connection_timeout_ms == 0) ep->config.connection_timeout_ms = 10000;
    if (ep->config.keepalive_interval_ms == 0) ep->config.keepalive_interval_ms = 1000;
    ep->sock = NL_INVALID_SOCKET;
    ep->discovery_sock = NL_INVALID_SOCKET;
    nl_crypto_random(ep->server_secret, 32);
    pthread_mutex_init(&ep->pending_lock, NULL);
    pthread_mutex_init(&ep->connections_lock, NULL);
    pthread_mutex_init(&ep->queue_lock, NULL);
    pthread_cond_init(&ep->queue_cond, NULL);
    return ep;
}

static nl_result_t start_io_thread(nl_endpoint_t *ep) {
    ep->running = true;
    if (pthread_create(&ep->io_thread, NULL, io_thread_main, ep) != 0) {
        ep->running = false;
        return NL_ERR_INTERNAL;
    }
    return NL_OK;
}

nl_result_t nl_server_create(const nl_address_t *bind_addr, const nl_config_t *cfg, nl_endpoint_t **out_endpoint) {
    if (!bind_addr || !out_endpoint) return NL_ERR_INVALID_ARGUMENT;
    nl_sockets_global_init();
    nl_config_t local_cfg;
    if (cfg) local_cfg = *cfg; else nl_config_default(&local_cfg);

    if (local_cfg.transport != NL_TRANSPORT_UDP) return NL_ERR_UNSUPPORTED; /* see docs/websocket for the other transport */

    nl_endpoint_t *ep = endpoint_alloc(true, &local_cfg);
    if (!ep) return NL_ERR_OUT_OF_MEMORY;

    struct sockaddr_storage addr; socklen_t addr_len; int family;
    if (!resolve_address(bind_addr, true, &addr, &addr_len, &family)) {
        free(ep);
        return NL_ERR_INVALID_ARGUMENT;
    }

    ep->sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (ep->sock == NL_INVALID_SOCKET) { free(ep); return NL_ERR_SOCKET; }

    int reuse = 1;
    setsockopt(ep->sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef IPV6_V6ONLY
    if (family == AF_INET6) {
        int v6only = 0; /* best-effort dual-stack; ignore failure */
        setsockopt(ep->sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }
#endif

    if (bind(ep->sock, (struct sockaddr *)&addr, addr_len) != 0) {
        nl_close_socket(ep->sock);
        free(ep);
        return NL_ERR_BIND_FAILED;
    }
    nl_socket_set_nonblocking(ep->sock);

    nl_result_t r = start_io_thread(ep);
    if (r != NL_OK) {
        nl_close_socket(ep->sock);
        free(ep);
        return r;
    }

    *out_endpoint = ep;
    return NL_OK;
}

nl_result_t nl_client_create(const nl_config_t *cfg, nl_endpoint_t **out_endpoint) {
    if (!out_endpoint) return NL_ERR_INVALID_ARGUMENT;
    nl_sockets_global_init();
    nl_config_t local_cfg;
    if (cfg) local_cfg = *cfg; else nl_config_default(&local_cfg);
    if (local_cfg.transport != NL_TRANSPORT_UDP) return NL_ERR_UNSUPPORTED;

    nl_endpoint_t *ep = endpoint_alloc(false, &local_cfg);
    if (!ep) return NL_ERR_OUT_OF_MEMORY;

    int family = (local_cfg.family == NL_AF_INET) ? AF_INET
               : (local_cfg.family == NL_AF_INET6) ? AF_INET6
               : AF_INET; /* default to IPv4 for the ephemeral client socket; connect() re-resolves per target */
    ep->sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (ep->sock == NL_INVALID_SOCKET) { free(ep); return NL_ERR_SOCKET; }
    nl_socket_set_nonblocking(ep->sock);

    nl_result_t r = start_io_thread(ep);
    if (r != NL_OK) {
        nl_close_socket(ep->sock);
        free(ep);
        return r;
    }

    *out_endpoint = ep;
    return NL_OK;
}

nl_result_t nl_connect(nl_endpoint_t *ep, const nl_address_t *server_addr, nl_peer_id_t *out_peer) {
    if (!ep || !server_addr || !out_peer || ep->is_server) return NL_ERR_INVALID_ARGUMENT;

    struct sockaddr_storage addr; socklen_t addr_len; int family;
    if (!resolve_address(server_addr, false, &addr, &addr_len, &family)) return NL_ERR_INVALID_ARGUMENT;

    nl_keypair_t *kp = nl_keypair_generate();
    if (!kp) return NL_ERR_CRYPTO;
    uint8_t pub[32];
    nl_keypair_public(kp, pub);
    uint8_t nonce[16];
    nl_crypto_random(nonce, 16);
    uint64_t connid;
    do {
        nl_crypto_random((uint8_t *)&connid, sizeof(connid));
    } while (connid == NL_INVALID_PEER);

    pthread_mutex_lock(&ep->pending_lock);
    pending_t *p = acquire_pending_slot_locked(ep, now_ms());
    p->in_use = true;
    p->role = PENDING_CLIENT_AWAIT_CHALLENGE;
    memcpy(&p->addr, &addr, sizeof(addr));
    p->addr_len = addr_len;
    p->my_keypair = kp;
    memcpy(p->my_nonce, nonce, 16);
    p->connection_id = connid;
    p->channel_count = ep->config.channel_count;
    p->created_ms = now_ms();
    pthread_mutex_unlock(&ep->pending_lock);

    uint8_t out[NL_CONNECT_REQUEST_SIZE];
    size_t o = 0;
    out[o++] = NL_PKT_CONNECT_REQUEST;
    nl_put_u32(out + o, NL_MAGIC); o += 4;
    nl_put_u16(out + o, NL_PROTOCOL_VERSION); o += 2;
    out[o++] = ep->config.channel_count;
    nl_put_u64(out + o, connid); o += 8;
    memcpy(out + o, pub, 32); o += 32;
    memcpy(out + o, nonce, 16); o += 16;

    sendto(ep->sock, out, o, 0, (struct sockaddr *)&addr, addr_len);

    *out_peer = connid;
    return NL_OK;
}

nl_result_t nl_disconnect(nl_endpoint_t *ep, nl_peer_id_t peer) {
    if (!ep) return NL_ERR_INVALID_ARGUMENT;
    pthread_mutex_lock(&ep->connections_lock);
    nl_connection_t *conn = find_connection_locked(ep, peer);
    if (!conn) { pthread_mutex_unlock(&ep->connections_lock); return NL_ERR_PEER_NOT_FOUND; }
    conn_ctx_t cctx = { ep, conn };
    nl_conn_callbacks_t cb = make_callbacks(&cctx);
    nl_connection_send_disconnect(conn, now_ms(), &cb);
    int slot = find_connection_slot_by_ptr_locked(ep, conn);
    if (slot >= 0) ep->connections[slot] = NULL;
    nl_connection_destroy(conn);
    pthread_mutex_unlock(&ep->connections_lock);
    return NL_OK;
}

void nl_endpoint_destroy(nl_endpoint_t *ep) {
    if (!ep) return;
    ep->running = false;
    pthread_join(ep->io_thread, NULL);

    for (int i = 0; i < NL_MAX_CONNECTIONS_INTERNAL; i++) {
        if (ep->connections[i]) nl_connection_destroy(ep->connections[i]);
    }
    for (int i = 0; i < NL_MAX_PENDING; i++) {
        if (ep->pending[i].in_use) release_pending_locked(&ep->pending[i]);
    }

    event_node_t *n = ep->queue_head;
    while (n) { event_node_t *next = n->next; free(n->payload); free(n); n = next; }
    free(ep->returned_owned_data);

    if (ep->sock != NL_INVALID_SOCKET) nl_close_socket(ep->sock);
    if (ep->discovery_sock != NL_INVALID_SOCKET) nl_close_socket(ep->discovery_sock);

    pthread_mutex_destroy(&ep->pending_lock);
    pthread_mutex_destroy(&ep->connections_lock);
    pthread_mutex_destroy(&ep->queue_lock);
    pthread_cond_destroy(&ep->queue_cond);

    memset(ep->server_secret, 0, sizeof(ep->server_secret));
    free(ep);
}

nl_result_t nl_send(nl_endpoint_t *ep, nl_peer_id_t peer, uint8_t channel, nl_delivery_t delivery,
                     const uint8_t *data, size_t len) {
    if (!ep || (len > 0 && !data)) return NL_ERR_INVALID_ARGUMENT;
    pthread_mutex_lock(&ep->connections_lock);
    nl_connection_t *conn = find_connection_locked(ep, peer);
    if (!conn) { pthread_mutex_unlock(&ep->connections_lock); return NL_ERR_PEER_NOT_FOUND; }
    conn_ctx_t cctx = { ep, conn };
    nl_conn_callbacks_t cb = make_callbacks(&cctx);
    nl_result_t r = nl_connection_send(conn, channel, delivery, data, len, now_ms(), &cb);
    pthread_mutex_unlock(&ep->connections_lock);
    return r;
}

bool nl_poll_event(nl_endpoint_t *ep, nl_event_t *out, int timeout_ms) {
    if (!ep || !out) return false;

    pthread_mutex_lock(&ep->queue_lock);
    if (ep->returned_owned_data) { free(ep->returned_owned_data); ep->returned_owned_data = NULL; }

    if (!ep->queue_head) {
        if (timeout_ms == 0) { pthread_mutex_unlock(&ep->queue_lock); return false; }
        if (timeout_ms < 0) {
            while (!ep->queue_head) pthread_cond_wait(&ep->queue_cond, &ep->queue_lock);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
            while (!ep->queue_head) {
                if (pthread_cond_timedwait(&ep->queue_cond, &ep->queue_lock, &ts) != 0) break;
            }
        }
        if (!ep->queue_head) { pthread_mutex_unlock(&ep->queue_lock); return false; }
    }

    event_node_t *node = ep->queue_head;
    ep->queue_head = node->next;
    if (!ep->queue_head) ep->queue_tail = NULL;
    pthread_mutex_unlock(&ep->queue_lock);

    *out = node->pub;
    if (node->payload) {
        out->data = node->payload;
        out->data_len = node->payload_len;
        ep->returned_owned_data = node->payload;
    } else {
        out->data = NULL;
        out->data_len = 0;
    }
    free(node);
    return true;
}

nl_result_t nl_discovery_enable(nl_endpoint_t *ep, uint16_t discovery_port) {
    if (!ep || !ep->is_server) return NL_ERR_INVALID_ARGUMENT;
    if (ep->discovery_sock != NL_INVALID_SOCKET) return NL_OK; /* already enabled */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(discovery_port);

    nl_socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == NL_INVALID_SOCKET) return NL_ERR_SOCKET;
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        nl_close_socket(sock);
        return NL_ERR_BIND_FAILED;
    }
    nl_socket_set_nonblocking(sock);
    ep->discovery_sock = sock;
    ep->discovery_port = discovery_port;
    return NL_OK;
}

nl_result_t nl_discovery_probe(nl_endpoint_t *ep, uint16_t discovery_port, int timeout_ms) {
    (void)timeout_ms; /* replies simply arrive as events over the following poll calls */
    if (!ep || ep->is_server) return NL_ERR_INVALID_ARGUMENT;

    nl_socket_t sock = ep->discovery_sock;
    if (sock == NL_INVALID_SOCKET) {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == NL_INVALID_SOCKET) return NL_ERR_SOCKET;
        int broadcast = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        nl_socket_set_nonblocking(sock);
        ep->discovery_sock = sock;
    }

    struct sockaddr_in bcast;
    memset(&bcast, 0, sizeof(bcast));
    bcast.sin_family = AF_INET;
    bcast.sin_port = htons(discovery_port);
    bcast.sin_addr.s_addr = INADDR_BROADCAST;

    uint32_t nonce = ++ep->discovery_probe_nonce;
    uint8_t out[NL_DISCOVERY_REQUEST_SIZE];
    out[0] = NL_PKT_DISCOVERY_REQUEST;
    nl_put_u32(out + 1, NL_MAGIC);
    nl_put_u32(out + 5, nonce);

    if (sendto(sock, out, sizeof(out), 0, (struct sockaddr *)&bcast, sizeof(bcast)) < 0) {
        return NL_ERR_SOCKET;
    }
    return NL_OK;
}

bool nl_peer_address(nl_endpoint_t *ep, nl_peer_id_t peer, nl_address_t *out) {
    if (!ep || !out) return false;
    pthread_mutex_lock(&ep->connections_lock);
    nl_connection_t *conn = find_connection_locked(ep, peer);
    bool found = conn != NULL;
    if (found) sockaddr_to_nl_address(&conn->addr, conn->addr_len, out);
    pthread_mutex_unlock(&ep->connections_lock);
    return found;
}

uint32_t nl_peer_rtt_ms(nl_endpoint_t *ep, nl_peer_id_t peer) {
    if (!ep) return 0;
    pthread_mutex_lock(&ep->connections_lock);
    nl_connection_t *conn = find_connection_locked(ep, peer);
    uint32_t rtt = 0;
    if (conn) rtt = nl_connection_rtt_ms(conn);
    pthread_mutex_unlock(&ep->connections_lock);
    return rtt;
}

uint32_t nl_peer_count(nl_endpoint_t *ep) {
    if (!ep) return 0;
    pthread_mutex_lock(&ep->connections_lock);
    uint32_t n = count_active_connections_locked(ep);
    pthread_mutex_unlock(&ep->connections_lock);
    return n;
}
