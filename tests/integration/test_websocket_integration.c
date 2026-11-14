/* Integration tests for WN_TRANSPORT_WEBSOCKET: real client + server over
 * loopback TCP, HTTP upgrade (RFC6455), then the normal encrypted weft-net
 * handshake and delivery modes inside binary WebSocket frames. */
#include "../test_framework.h"
#include "../../include/weft_net.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

static bool wait_for_event(wn_endpoint_t *ep, wn_event_type_t type, wn_event_t *out, int timeout_ms) {
    uint64_t iterations = (uint64_t)timeout_ms / 50 + 1;
    for (uint64_t i = 0; i < iterations; i++) {
        if (wn_poll_event(ep, out, 50)) {
            if (out->event_type == type) return true;
        }
    }
    return false;
}

static wn_address_t addr(const char *host, uint16_t port) {
    wn_address_t a; memset(&a, 0, sizeof(a));
    strncpy(a.host, host, sizeof(a.host) - 1);
    a.port = port;
    a.family = WN_AF_UNSPEC;
    return a;
}

static void ws_config(wn_config_t *cfg) {
    wn_config_default(cfg);
    cfg->transport = WN_TRANSPORT_WEBSOCKET;
}

TEST(test_ws_connect_and_reliable_echo) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL, *client = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34751);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);

    wn_peer_id_t client_peer;
    ASSERT_EQ(wn_connect(client, &bind_addr, &client_peer), WN_OK);

    wn_event_t ev;
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_CONNECTED, &ev, 5000));
    wn_peer_id_t server_peer = ev.peer;

    const char *msg = "websocket hello";
    ASSERT_EQ(wn_send(client, client_peer, 0, WN_RELIABLE_ORDERED,
                      (const uint8_t *)msg, strlen(msg)), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.data_len, strlen(msg));
    ASSERT_MEM_EQ(ev.data, msg, strlen(msg));

    const char *reply = "echo from ws server";
    ASSERT_EQ(wn_send(server, server_peer, 0, WN_RELIABLE_ORDERED,
                      (const uint8_t *)reply, strlen(reply)), WN_OK);
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.data_len, strlen(reply));
    ASSERT_MEM_EQ(ev.data, reply, strlen(reply));

    wn_endpoint_destroy(client);
    wn_endpoint_destroy(server);
}

TEST(test_ws_unreliable_delivery) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL, *client = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34752);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);

    wn_peer_id_t client_peer;
    ASSERT_EQ(wn_connect(client, &bind_addr, &client_peer), WN_OK);
    wn_event_t ev;
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_CONNECTED, &ev, 5000));

    const uint8_t payload[] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(wn_send(client, client_peer, 2, WN_UNRELIABLE, payload, sizeof(payload)), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.channel, 2);
    ASSERT_EQ(ev.data_len, sizeof(payload));
    ASSERT_MEM_EQ(ev.data, payload, sizeof(payload));

    wn_endpoint_destroy(client);
    wn_endpoint_destroy(server);
}

TEST(test_ws_fragmented_large_message) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL, *client = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34753);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);

    wn_peer_id_t client_peer;
    ASSERT_EQ(wn_connect(client, &bind_addr, &client_peer), WN_OK);
    wn_event_t ev;
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_CONNECTED, &ev, 5000));

    size_t big_len = 5000;
    uint8_t *big = (uint8_t *)malloc(big_len);
    ASSERT_TRUE(big != NULL);
    for (size_t i = 0; i < big_len; i++) big[i] = (uint8_t)((i * 13 + 7) & 0xFF);

    ASSERT_EQ(wn_send(client, client_peer, 0, WN_RELIABLE_ORDERED, big, big_len), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 10000));
    ASSERT_EQ(ev.data_len, big_len);
    ASSERT_MEM_EQ(ev.data, big, big_len);

    free(big);
    wn_endpoint_destroy(client);
    wn_endpoint_destroy(server);
}

TEST(test_ws_discovery_unsupported) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34754);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_discovery_enable(server, 34999), WN_ERR_UNSUPPORTED);
    wn_endpoint_destroy(server);

    wn_endpoint_t *client = NULL;
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);
    ASSERT_EQ(wn_discovery_probe(client, 34999, 100), WN_ERR_UNSUPPORTED);
    wn_endpoint_destroy(client);
}

TEST(test_ws_rejects_cleartext_config) {
    wn_config_t cfg; ws_config(&cfg);
    cfg.encryption_enabled = false;
    wn_endpoint_t *ep = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34755);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &ep), WN_ERR_UNSUPPORTED);
    ASSERT_EQ(wn_client_create(&cfg, &ep), WN_ERR_UNSUPPORTED);
}

/* Test-only helpers from endpoint.c, declared in tests/test_helpers.h. */
#include "../test_helpers.h"

/* Regression (P1-4): the WebSocket immediate-connect path (nonblocking
 * connect() succeeding synchronously on loopback) leaked its pending entry
 * when ws_client_finish_connect failed -- no release, so the slot stayed
 * in_use until the 5s expiry. A synchronously-failed wn_connect must leave
 * no pending entry behind (checked here via the async-failure shape, which
 * exercises the same release accounting; the immediate path is covered by
 * the release_pending_by_connid call in wn_connect). */
TEST(test_ws_failed_connect_does_not_leak_pending) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *client = NULL;
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
    wn_event_t ev;

    /* Phase 1: closed port (dial refused). Synchronous refusal: no entry
     * may leak. */
    wn_address_t closed = addr("127.0.0.1", 34760);
    wn_peer_id_t peer = 0;
    wn_result_t r = wn_connect(client, &closed, &peer);
    if (r != WN_OK) {
        /* Synchronous refusal (e.g. immediate RST): no entry may leak. */
        ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
        wn_endpoint_destroy(client);
        return;
    }
    /* Async path: one entry in flight. */
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 1);
    bool failed = wait_for_event(client, WN_EVENT_CONNECT_FAILED, &ev, 6000);
    /* Either CONNECT_FAILED (pending released via drop_peer_state) or a
     * 5s expiry (pending released via expire_pending): both must drain. */
    if (failed) {
        ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
    } else {
        /* No event yet: expiry hasn't fired; at most the one entry remains. */
        ASSERT_TRUE(wn_endpoint_pending_used_for_test(client) <= 1);
        /* Wait for the 5s pending timeout to reclaim it. */
        ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECT_FAILED, &ev, 6000));
        ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
    }
    wn_endpoint_destroy(client);
}

/* R3 follow-up to the above: an accept-then-RST listener. The listener
 * accepts the TCP connection and immediately closes it with SO_LINGER
 * zero, so the client's poll cycle sees POLLOUT (or POLLERR) and
 * ws_client_finish_connect must fail through getsockopt/send -- the real
 * socket-path failure branch behind the pending-leak fix (the
 * release_pending_by_connid fallback in wn_connect, and
 * ws_link_drop_peer_state's release). Assert the pending entry drains
 * and a CONNECT_FAILED event is actually delivered. */
TEST(test_ws_rst_listener_leaks_nothing) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *client = NULL;
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);

    int lst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_TRUE(lst >= 0);
    int one = 1;
    setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(34776);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    ASSERT_EQ(bind(lst, (struct sockaddr *)&sa, sizeof(sa)), 0);
    ASSERT_EQ(listen(lst, 4), 0);

    wn_address_t rst_addr = addr("127.0.0.1", 34776);
    wn_peer_id_t peer = 0;
    wn_result_t r = wn_connect(client, &rst_addr, &peer);
    ASSERT_EQ(r, WN_OK); /* dial-out is always synchronous-OK (async TCP) */
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 1);

    /* Accept whatever lands and close with zero linger: RST to the
     * client. Accepts can lag the kernel handshake by a poll cycle. */
    for (long long t = 0; t < 3000; t += 20) {
        struct pollfd pf = { .fd = lst, .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 20) > 0 && (pf.revents & POLLIN)) {
            struct sockaddr_storage peer_sa; socklen_t plen = sizeof(peer_sa);
            int c = accept(lst, (struct sockaddr *)&peer_sa, &plen);
            ASSERT_TRUE(c >= 0);
            struct linger lg = { .l_onoff = 1, .l_linger = 0 };
            setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
            close(c);
            wn_event_t ev;
            bool failed = wait_for_event(client, WN_EVENT_CONNECT_FAILED, &ev, 6000);
            CHECK_TRUE(failed); /* surface the failure, not just expiry */
            ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
            close(lst);
            wn_endpoint_destroy(client);
            return; /* success */
        }
    }
    close(lst);
    wn_endpoint_destroy(client);
    WN_FAIL("%s", "listener never saw the dial-out connection");
}

/* M2 (the ws-link reap sweep in endpoint.c): raw TCP "peers" that land on
 * a WebSocket server port but never complete the HTTP upgrade previously
 * held their socket + decoder memory for as long as the TCP connection
 * lived (nothing else releases such links). After the fix the IO thread
 * closes any link that has not upgraded within WN_WS_CONNECT_TIMEOUT_MS
 * (10s). */
TEST(test_ws_reaps_pre_upgrade_links) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34975);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_TRUE(wn_endpoint_ws_links_used_for_test(server) == 0);

    /* Three raw TCP sockets that connect and then say nothing at all: no
     * HTTP request, no WebSocket frames, nothing to release them on the
     * old code. */
    int socks[3];
    for (int i = 0; i < 3; i++) {
        socks[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ASSERT_TRUE(socks[i] >= 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(bind_addr.port);
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");
        ASSERT_EQ(connect(socks[i], (struct sockaddr *)&sa, sizeof(sa)), 0);
    }

    /* Accepted links appear; nothing else may kick them off. */
    for (long long t = 0; t < 3000; t += 50) {
        if (wn_endpoint_ws_links_used_for_test(server) == 3) break;
        usleep(50 * 1000);
    }
    ASSERT_TRUE(wn_endpoint_ws_links_used_for_test(server) == 3);

    /* The reap sweep must close them past WN_WS_CONNECT_TIMEOUT_MS. */
    for (long long t = 0; t < 12000; t += 200) {
        if (wn_endpoint_ws_links_used_for_test(server) == 0) break;
        usleep(200 * 1000);
    }
    ASSERT_TRUE(wn_endpoint_ws_links_used_for_test(server) == 0);

    for (int i = 0; i < 3; i++) close(socks[i]);
    wn_endpoint_destroy(server);
}

int main(void) {
    printf("websocket integration tests\n");
    RUN_TEST(test_ws_connect_and_reliable_echo);
    RUN_TEST(test_ws_unreliable_delivery);
    RUN_TEST(test_ws_fragmented_large_message);
    RUN_TEST(test_ws_discovery_unsupported);
    RUN_TEST(test_ws_rejects_cleartext_config);
    RUN_TEST(test_ws_failed_connect_does_not_leak_pending);
    RUN_TEST(test_ws_rst_listener_leaks_nothing);
    RUN_TEST(test_ws_reaps_pre_upgrade_links);
    TEST_SUMMARY();
}
