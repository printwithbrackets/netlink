/* test_threading.c - concurrency tests for the public endpoint API.
 *
 * The rest of the suite runs every test on one thread, which cannot reach
 * the races between the endpoint's I/O thread and user threads: the
 * per-thread payload borrow in nl_poll_event, ep->io_thread_started, the
 * connection table, and the pending-handshake table. These tests are meant
 * to be run under ThreadSanitizer (`make test-tsan`); under ASan they still
 * catch outright memory errors.
 *
 * Each test spawns real threads against a real client/server pair over
 * loopback, so they exercise the shipped locking discipline rather than a
 * model of it.
 */
#include "../test_framework.h"
#include "../../include/netlink.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

static nl_address_t addr(uint16_t port) {
    nl_address_t a;
    memset(&a, 0, sizeof(a));
    strncpy(a.host, "127.0.0.1", sizeof(a.host) - 1);
    a.port = port;
    a.family = NL_AF_UNSPEC;
    return a;
}

static bool wait_for_event(nl_endpoint_t *ep, nl_event_type_t type, nl_event_t *out, int timeout_ms) {
    uint64_t iterations = (uint64_t)timeout_ms / 50 + 1;
    for (uint64_t i = 0; i < iterations; i++) {
        if (nl_poll_event(ep, out, 50)) {
            if (out->event_type == type) return true;
        }
    }
    return false;
}

/* Connect a client to a server on `port`; returns both, with the client's
 * peer id for the server. */
static void make_pair_ex(nl_endpoint_t **server, nl_endpoint_t **client, nl_peer_id_t *client_peer,
                         uint16_t port, uint32_t recv_window_bytes, uint32_t client_timeout_ms) {
    nl_config_t scfg, ccfg;
    nl_config_default(&scfg);
    nl_config_default(&ccfg);
    scfg.recv_window_bytes = recv_window_bytes;
    if (client_timeout_ms) ccfg.connection_timeout_ms = client_timeout_ms;
    nl_address_t bind_addr = addr(port);
    ASSERT_EQ(nl_server_create(&bind_addr, &scfg, server), NL_OK);
    ASSERT_EQ(nl_client_create(&ccfg, client), NL_OK);
    ASSERT_EQ(nl_connect(*client, &bind_addr, client_peer), NL_OK);

    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(*client, NL_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(*server, NL_EVENT_CONNECTED, &ev, 5000));
}

static void make_pair(nl_endpoint_t **server, nl_endpoint_t **client, nl_peer_id_t *client_peer,
                      uint16_t port, uint32_t recv_window_bytes) {
    make_pair_ex(server, client, client_peer, port, recv_window_bytes, 0);
}

/* ---- 1: several threads polling the same endpoint ---- */

#define CONCURRENT_POLLERS 4
#define POLLS_PER_THREAD 120
#define POLL_PAYLOAD_LEN 64
#define POLL_PAYLOAD_BYTE 0xC3

typedef struct {
    nl_endpoint_t *ep;
    int delivered;
    int corrupted;
    int missing;
    /* Per-poll budget. Tests that send a known count set this low, so
     * under-delivery surfaces as a count mismatch instead of a 10s stall
     * per missing message. */
    int timeout_ms;
} poll_ctx_t;

static void *poll_main(void *arg) {
    poll_ctx_t *c = (poll_ctx_t *)arg;
    if (c->timeout_ms == 0) c->timeout_ms = 10000;
    for (int i = 0; i < POLLS_PER_THREAD; i++) {
        nl_event_t ev;
        if (!nl_poll_event(c->ep, &ev, c->timeout_ms)) { c->missing++; continue; }
        if (ev.event_type != NL_EVENT_DATA) continue;
        /* The borrow belongs to THIS thread until its next poll; reading it
         * here is exactly the pattern the shared slot used to break. */
        if (ev.data_len != POLL_PAYLOAD_LEN) { c->corrupted++; continue; }
        for (uint32_t k = 0; k < ev.data_len; k++) {
            if (ev.data[k] != POLL_PAYLOAD_BYTE) { c->corrupted++; break; }
        }
        c->delivered++;
    }
    return NULL;
}

TEST(test_threading_concurrent_pollers) {
    nl_endpoint_t *server, *client;
    nl_peer_id_t client_peer;
    make_pair(&server, &client, &client_peer, 34901, 0);

    const int total = CONCURRENT_POLLERS * POLLS_PER_THREAD;
    pthread_t threads[CONCURRENT_POLLERS];
    poll_ctx_t ctxs[CONCURRENT_POLLERS];
    for (int t = 0; t < CONCURRENT_POLLERS; t++) {
        memset(&ctxs[t], 0, sizeof(ctxs[t]));
        ctxs[t].ep = server;
        ctxs[t].timeout_ms = 10000; /* exactly `total` messages are coming */
    }
    for (int t = 0; t < CONCURRENT_POLLERS; t++) {
        ASSERT_EQ(pthread_create(&threads[t], NULL, poll_main, &ctxs[t]), 0);
    }

    uint8_t payload[POLL_PAYLOAD_LEN];
    memset(payload, POLL_PAYLOAD_BYTE, sizeof(payload));
    int sent = 0, idle = 0;
    while (sent < total && idle < 300) {
        if (nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, payload, sizeof(payload)) == NL_OK) {
            sent++;
            idle = 0;
            continue;
        }
        usleep(2000); /* window-gated; back off rather than fill the queue */
        idle++;
    }
    CHECK_EQ(sent, total);

    for (int t = 0; t < CONCURRENT_POLLERS; t++) pthread_join(threads[t], NULL);

    int corrupted = 0, missing = 0, delivered = 0;
    for (int t = 0; t < CONCURRENT_POLLERS; t++) {
        corrupted += ctxs[t].corrupted;
        missing += ctxs[t].missing;
        delivered += ctxs[t].delivered;
    }
    if (corrupted || missing) {
        printf("    corrupted %d, timed out %d, delivered %d\n", corrupted, missing, delivered);
    }
    ASSERT_EQ(corrupted, 0);
    ASSERT_EQ(missing, 0);
    ASSERT_EQ(delivered, total);

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

/* ---- 2: many senders against one poller ---- */

#define SENDERS 6
#define SENDS_PER_THREAD 60

typedef struct {
    nl_endpoint_t *ep;
    nl_peer_id_t peer;
    uint8_t tag;
    int accepted;
    int rejected;
} sender_ctx_t;

static void *sender_main(void *arg) {
    sender_ctx_t *c = (sender_ctx_t *)arg;
    uint8_t payload[32];
    memset(payload, c->tag, sizeof(payload));
    for (int i = 0; i < SENDS_PER_THREAD; i++) {
        /* Retry on NL_ERR_QUEUE_FULL: the per-connection deferred queue is a
         * documented, finite bound (128 messages), and with 6 senders
         * hammering a closed window some sends legitimately hit it. This
         * test is about concurrent send/poll correctness, not about that
         * bound -- test_send_queue_full_returns_error covers the bound. */
        for (int attempt = 0; attempt < 200; attempt++) {
            nl_result_t r = nl_send(c->ep, c->peer, 0, NL_RELIABLE_ORDERED,
                                    payload, sizeof(payload));
            if (r == NL_OK) { c->accepted++; break; }
            if (r != NL_ERR_QUEUE_FULL) { c->rejected++; break; }
            usleep(1000); /* let the drainer reopen the window */
        }
    }
    return NULL;
}

/* Continuously drains the receiver so its window keeps reopening. Without
 * one, a small window closes, the senders fill the deferred queue, and
 * sends start legitimately returning NL_ERR_QUEUE_FULL -- this test is about
 * send/poll concurrency, not backpressure. */
typedef struct {
    nl_endpoint_t *ep;
    atomic_bool stop; /* atomic, not volatile: a stop flag read across
                       * threads is synchronisation, not a hint */
    int counts[SENDERS]; /* per-sender messages verified intact */
    int bad;
} drain_ctx_t;

static void *drain_main(void *arg) {
    drain_ctx_t *d = (drain_ctx_t *)arg;
    while (!atomic_load(&d->stop)) {
        nl_event_t ev;
        if (!nl_poll_event(d->ep, &ev, 100)) continue;
        if (ev.event_type != NL_EVENT_DATA) continue;
        if (ev.data_len != 32u) { d->bad++; continue; }
        uint8_t tag = ev.data[0];
        int t = (int)tag - 0x40;
        if (t < 0 || t >= SENDERS) { d->bad++; continue; }
        for (uint32_t k = 0; k < ev.data_len; k++) {
            if (ev.data[k] != tag) { d->bad++; break; }
        }
        d->counts[t]++;
    }
    return NULL;
}

TEST(test_threading_many_senders_one_poller) {
    nl_endpoint_t *server, *client;
    nl_peer_id_t client_peer;
    /* A small receive window forces the deferred queue and its priority
     * sorting to be exercised concurrently with polling. */
    make_pair(&server, &client, &client_peer, 34902, 8192);

    drain_ctx_t drain;
    memset(&drain, 0, sizeof(drain));
    drain.ep = server;
    pthread_t drainer;
    ASSERT_EQ(pthread_create(&drainer, NULL, drain_main, &drain), 0);

    pthread_t threads[SENDERS];
    sender_ctx_t ctxs[SENDERS];
    for (int t = 0; t < SENDERS; t++) {
        memset(&ctxs[t], 0, sizeof(ctxs[t]));
        ctxs[t].ep = client;
        ctxs[t].peer = client_peer;
        ctxs[t].tag = (uint8_t)(0x40 + t);
    }
    for (int t = 0; t < SENDERS; t++) {
        ASSERT_EQ(pthread_create(&threads[t], NULL, sender_main, &ctxs[t]), 0);
    }
    for (int t = 0; t < SENDERS; t++) pthread_join(threads[t], NULL);

    /* Everything must have gone out: with the window being drained, no send
     * should have hit the deferred queue's bound. */
    int total_accepted = 0, total_rejected = 0;
    for (int t = 0; t < SENDERS; t++) {
        total_accepted += ctxs[t].accepted;
        total_rejected += ctxs[t].rejected;
    }
    if (total_rejected) printf("    %d sends rejected\n", total_rejected);
    ASSERT_EQ(total_accepted, SENDERS * SENDS_PER_THREAD);
    ASSERT_EQ(total_rejected, 0);

    /* Drain whatever is left here, then check every accepted message arrived
     * exactly once and intact. Per-sender counts, since which thread receives
     * which message isn't deterministic. */
    atomic_store(&drain.stop, true);
    pthread_join(drainer, NULL);

    int counts[SENDERS];
    memcpy(counts, drain.counts, sizeof(counts));
    for (int i = 0; i < total_accepted + 500; i++) {
        nl_event_t ev;
        if (!nl_poll_event(server, &ev, 1000)) break;
        if (ev.event_type != NL_EVENT_DATA) continue;
        ASSERT_EQ(ev.data_len, 32u);
        uint8_t tag = ev.data[0];
        int t = (int)tag - 0x40;
        ASSERT_TRUE(t >= 0 && t < SENDERS);
        for (uint32_t k = 0; k < ev.data_len; k++) ASSERT_EQ(ev.data[k], tag);
        counts[t]++;
    }
    if (drain.bad) printf("    %d corrupted payloads in the drain thread\n", drain.bad);
    ASSERT_EQ(drain.bad, 0);
    for (int t = 0; t < SENDERS; t++) {
        if (counts[t] != ctxs[t].accepted) {
            printf("    sender %d: accepted %d, received %d\n", t, ctxs[t].accepted, counts[t]);
        }
        CHECK_EQ(counts[t], ctxs[t].accepted);
    }

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

/* ---- 3: polling and sending on the same endpoint, concurrently ---- */

TEST(test_threading_send_and_poll_concurrently) {
    nl_endpoint_t *server, *client;
    nl_peer_id_t client_peer;
    make_pair(&server, &client, &client_peer, 34903, 0);

    pthread_t poller;
    poll_ctx_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.ep = client;
    pc.timeout_ms = 200; /* far fewer messages than POLLS_PER_THREAD */
    ASSERT_EQ(pthread_create(&poller, NULL, poll_main, &pc), 0);

    /* Send from the main thread while that poller is running: both the
     * endpoint's queue_lock and its connections_lock are contended. */
    uint8_t payload[POLL_PAYLOAD_LEN];
    memset(payload, POLL_PAYLOAD_BYTE, sizeof(payload));
    int accepted = 0;
    for (int i = 0; i < 200; i++) {
        if (nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, payload, sizeof(payload)) == NL_OK) {
            accepted++;
        }
    }
    pthread_join(poller, NULL);
    CHECK_TRUE(accepted > 0);

    /* Drain the server side so nothing is left mid-flight at destroy. */
    int seen = 0;
    for (int i = 0; i < accepted + 200; i++) {
        nl_event_t ev;
        if (!nl_poll_event(server, &ev, 3000)) break;
        if (ev.event_type == NL_EVENT_DATA) seen++;
    }
    CHECK_EQ(seen, accepted);

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

/* ---- 4: disconnect racing in-flight traffic ---- */

typedef struct {
    nl_endpoint_t *ep;
    nl_peer_id_t peer;
    uint8_t tag;
} closer_ctx_t;

static void *closer_main(void *arg) {
    closer_ctx_t *c = (closer_ctx_t *)arg;
    nl_endpoint_destroy(c->ep);
    (void)c->peer; (void)c->tag;
    return NULL;
}

TEST(test_threading_destroy_races_in_flight_traffic) {
    /* Create and destroy a live connection repeatedly while the I/O thread
     * is mid-cycle, on a background thread, so the destroy/teardown path
     * runs concurrently with packet processing. */
    for (int iter = 0; iter < 12; iter++) {
        nl_endpoint_t *server, *client;
        nl_peer_id_t client_peer;
        /* A short client idle timeout: the server vanishing sends nothing
         * over UDP (no RST, no DISCONNECT), so the client can only discover
         * the peer is gone by timing out. Without a short timeout the
         * post-destroy assertions below would sit for the 10s default. */
        make_pair_ex(&server, &client, &client_peer, (uint16_t)(34910 + iter), 0,
                     /*client_timeout_ms*/ 600);

/* The sender keeps hammering the *server* (still valid from the client's
         * side) while the server is destroyed underneath: the server's I/O
         * thread, connection teardown, pending table, and event queue are
         * all torn down concurrently with inbound packets and with the
         * client's own I/O thread seeing the connection vanish.
         *
         * Note what is deliberately NOT done here: calling nl_send on an
         * endpoint from another thread while that same endpoint is being
         * destroyed. The API makes peer handles invalid at destroy, so that
         * would be a use-after-free in the test rather than a real race. */
        pthread_t sender;
        sender_ctx_t sc;
        memset(&sc, 0, sizeof(sc));
        sc.ep = client;
        sc.peer = client_peer;
        ASSERT_EQ(pthread_create(&sender, NULL, sender_main, &sc), 0);

        closer_ctx_t cc = { server, client_peer, 0xFF };
        pthread_t closer;
        ASSERT_EQ(pthread_create(&closer, NULL, closer_main, &cc), 0);

        pthread_join(closer, NULL);
        pthread_join(sender, NULL);

        /* The client must survive its peer vanishing mid-traffic: it times
         * out, reports DISCONNECTED, and subsequent sends fail cleanly --
         * no crash, no hang, no silent success. */
        bool saw_disconnect = false;
        for (int i = 0; i < 200; i++) {
            nl_event_t ev;
            if (!nl_poll_event(client, &ev, 100)) continue;
            if (ev.event_type == NL_EVENT_DISCONNECTED) { saw_disconnect = true; break; }
        }
        CHECK_TRUE(saw_disconnect);
        nl_result_t r = nl_send(client, client_peer, 0, NL_UNRELIABLE,
                                (const uint8_t *)"x", 1);
        if (r == NL_OK) {
            printf("    post-disconnect send still accepted (peer %llu)\n",
                   (unsigned long long)client_peer);
        }
        CHECK_EQ(r, NL_ERR_PEER_NOT_FOUND);

        nl_endpoint_destroy(client);
    }
}

/* ---- 5: concurrent connects to one server ---- */

#define RACERS 5

typedef struct {
    nl_endpoint_t *ep;
    uint16_t port;
    int connected;
    int errors;
} racer_ctx_t;

static void *racer_main(void *arg) {
    racer_ctx_t *c = (racer_ctx_t *)arg;
    nl_address_t bind_addr = addr(c->port);
    nl_peer_id_t peer;
    if (nl_connect(c->ep, &bind_addr, &peer) != NL_OK) { c->errors++; return NULL; }
    nl_event_t ev;
    if (wait_for_event(c->ep, NL_EVENT_CONNECTED, &ev, 5000)) c->connected++;
    else c->errors++;
    return NULL;
}

TEST(test_threading_concurrent_connects) {
    nl_config_t scfg;
    nl_config_default(&scfg);
    nl_address_t bind_addr = addr(34930);
    nl_endpoint_t *server = NULL;
    ASSERT_EQ(nl_server_create(&bind_addr, &scfg, &server), NL_OK);

    pthread_t threads[RACERS];
    racer_ctx_t ctxs[RACERS];
    for (int t = 0; t < RACERS; t++) {
        memset(&ctxs[t], 0, sizeof(ctxs[t]));
        nl_config_t ccfg;
        nl_config_default(&ccfg);
        ASSERT_EQ(nl_client_create(&ccfg, &ctxs[t].ep), NL_OK);
        ctxs[t].port = bind_addr.port;
    }
    for (int t = 0; t < RACERS; t++) {
        ASSERT_EQ(pthread_create(&threads[t], NULL, racer_main, &ctxs[t]), 0);
    }
    for (int t = 0; t < RACERS; t++) pthread_join(threads[t], NULL);

    int connected = 0;
    for (int t = 0; t < RACERS; t++) {
        connected += ctxs[t].connected;
        CHECK_EQ(ctxs[t].errors, 0);
        nl_endpoint_destroy(ctxs[t].ep);
    }
    CHECK_EQ(connected, RACERS);
    CHECK_EQ(nl_peer_count(server), (int)RACERS);

    nl_endpoint_destroy(server);
}

int main(void) {
    printf("=== threading tests ===\n");
    RUN_TEST(test_threading_concurrent_pollers);
    RUN_TEST(test_threading_many_senders_one_poller);
    RUN_TEST(test_threading_send_and_poll_concurrently);
    RUN_TEST(test_threading_destroy_races_in_flight_traffic);
    RUN_TEST(test_threading_concurrent_connects);
    TEST_SUMMARY();
}