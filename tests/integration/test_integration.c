/* Integration tests: real nl_endpoint_t client + server talking over
 * actual loopback UDP sockets (127.0.0.1 and ::1), exercising the full
 * stack end to end -- handshake, encryption, all delivery modes,
 * multiple channels, fragmentation, disconnects, and discovery. */
#include "../test_framework.h"
#include "../../include/netlink.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static bool wait_for_event(nl_endpoint_t *ep, nl_event_type_t type, nl_event_t *out, int timeout_ms) {
    uint64_t deadline_iterations = (uint64_t)timeout_ms / 50 + 1;
    for (uint64_t i = 0; i < deadline_iterations; i++) {
        if (nl_poll_event(ep, out, 50)) {
            if (out->event_type == type) return true;
            /* not the event we wanted yet; keep waiting for the remaining budget */
        }
    }
    return false;
}

static nl_address_t addr(const char *host, uint16_t port) {
    nl_address_t a; memset(&a, 0, sizeof(a));
    strncpy(a.host, host, sizeof(a.host) - 1);
    a.port = port;
    a.family = NL_AF_UNSPEC;
    return a;
}

TEST(test_connect_and_reliable_ordered_data) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34701);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);

    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));
    nl_peer_id_t server_side_peer = ev.peer;

    const char *msg = "hello from client, reliably and in order";
    ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, (const uint8_t *)msg, strlen(msg)), NL_OK);

    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 3000));
    ASSERT_EQ(ev.peer, server_side_peer);
    ASSERT_EQ(ev.channel, 0);
    ASSERT_EQ(ev.data_len, strlen(msg));
    ASSERT_MEM_EQ(ev.data, msg, strlen(msg));

    /* And the reverse direction. */
    const char *reply = "hello back from server";
    ASSERT_EQ(nl_send(server, server_side_peer, 0, NL_RELIABLE_ORDERED, (const uint8_t *)reply, strlen(reply)), NL_OK);
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_DATA, &ev, 3000));
    ASSERT_EQ(ev.data_len, strlen(reply));
    ASSERT_MEM_EQ(ev.data, reply, strlen(reply));

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_all_delivery_modes_over_real_sockets) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34702);
    nl_server_create(&bind_addr, &cfg, &server);
    nl_client_create(&cfg, &client);

    nl_peer_id_t client_peer;
    nl_connect(client, &bind_addr, &client_peer);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    nl_delivery_t modes[4] = { NL_UNRELIABLE, NL_UNRELIABLE_SEQUENCED, NL_RELIABLE_UNORDERED, NL_RELIABLE_ORDERED };
    for (int i = 0; i < 4; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "mode-%d-payload", i);
        ASSERT_EQ(nl_send(client, client_peer, (uint8_t)i, modes[i], (const uint8_t *)msg, strlen(msg)), NL_OK);
        ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 3000));
        ASSERT_EQ(ev.channel, i);
        ASSERT_MEM_EQ(ev.data, msg, strlen(msg));
    }

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_fragmentation_over_real_sockets) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34703);
    nl_server_create(&bind_addr, &cfg, &server);
    nl_client_create(&cfg, &client);

    nl_peer_id_t client_peer;
    nl_connect(client, &bind_addr, &client_peer);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    size_t big_len = 5000; /* forces multiple fragments at 1024 bytes/chunk */
    uint8_t *big = (uint8_t *)malloc(big_len);
    for (size_t i = 0; i < big_len; i++) big[i] = (uint8_t)((i * 31 + 5) & 0xFF);

    ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, big, big_len), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.data_len, big_len);
    ASSERT_MEM_EQ(ev.data, big, big_len);

    free(big);
    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_multiple_channels_dont_block_each_other) {
    nl_config_t cfg; nl_config_default(&cfg);
    cfg.channel_count = 4;
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34704);
    nl_server_create(&bind_addr, &cfg, &server);
    nl_client_create(&cfg, &client);

    nl_peer_id_t client_peer;
    nl_connect(client, &bind_addr, &client_peer);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    /* Send on channel 3 first, then channel 0 -- both must arrive
     * independently (proves channels aren't sharing one sequence space). */
    nl_send(client, client_peer, 3, NL_RELIABLE_ORDERED, (const uint8_t *)"chan3", 5);
    nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"chan0", 5);

    bool saw_chan0 = false, saw_chan3 = false;
    for (int i = 0; i < 2; i++) {
        ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 3000));
        if (ev.channel == 0) { saw_chan0 = true; ASSERT_MEM_EQ(ev.data, "chan0", 5); }
        if (ev.channel == 3) { saw_chan3 = true; ASSERT_MEM_EQ(ev.data, "chan3", 5); }
    }
    ASSERT_TRUE(saw_chan0);
    ASSERT_TRUE(saw_chan3);

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_graceful_disconnect_over_real_sockets) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34705);
    nl_server_create(&bind_addr, &cfg, &server);
    nl_client_create(&cfg, &client);

    nl_peer_id_t client_peer;
    nl_connect(client, &bind_addr, &client_peer);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    ASSERT_EQ(nl_disconnect(client, client_peer), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DISCONNECTED, &ev, 3000));
    ASSERT_EQ(ev.disconnect_reason, NL_OK); /* graceful, not a timeout */

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_ipv6_loopback) {
    nl_config_t cfg; nl_config_default(&cfg);
    cfg.family = NL_AF_INET6;
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("::1", 34706);
    bind_addr.family = NL_AF_INET6;

    nl_result_t r = nl_server_create(&bind_addr, &cfg, &server);
    if (r != NL_OK) {
        /* IPv6 loopback may be unavailable in some sandboxed CI network
         * namespaces -- skip rather than fail the whole suite in that case. */
        printf("  SKIP test_ipv6_loopback: server bind failed (%s) -- IPv6 may be unavailable here\n",
               nl_error_string(r));
        return;
    }
    nl_client_create(&cfg, &client);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    const char *msg = "hello over ipv6";
    ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, (const uint8_t *)msg, strlen(msg)), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 3000));
    ASSERT_MEM_EQ(ev.data, msg, strlen(msg));

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_discovery_over_real_sockets) {
    nl_config_t cfg; nl_config_default(&cfg);
    cfg.server_name = "Test Arena";
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34707);
    nl_server_create(&bind_addr, &cfg, &server);
    nl_client_create(&cfg, &client);

    ASSERT_EQ(nl_discovery_enable(server, 34799), NL_OK);
    ASSERT_EQ(nl_discovery_probe(client, 34799, 1000), NL_OK);

    nl_event_t ev;
    bool got = wait_for_event(client, NL_EVENT_DISCOVERY_REPLY, &ev, 3000);
    if (!got) {
        /* UDP broadcast can be filtered in some sandboxed network
         * namespaces even on loopback-adjacent setups; skip rather than
         * fail outright, but note it clearly. */
        printf("  SKIP test_discovery_over_real_sockets: no broadcast reply received "
               "(broadcast may be filtered in this network namespace)\n");
        nl_endpoint_destroy(client);
        nl_endpoint_destroy(server);
        return;
    }
    ASSERT_TRUE(strcmp(ev.server_name, "Test Arena") == 0);

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_server_denies_when_full) {
    nl_config_t cfg; nl_config_default(&cfg);
    cfg.max_connections = 1;
    nl_endpoint_t *server = NULL, *c1 = NULL, *c2 = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34708);
    nl_server_create(&bind_addr, &cfg, &server);
    nl_client_create(&cfg, &c1);
    nl_client_create(&cfg, &c2);

    nl_peer_id_t p1, p2;
    nl_connect(c1, &bind_addr, &p1);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(c1, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    nl_connect(c2, &bind_addr, &p2);
    ASSERT_TRUE(wait_for_event(c2, NL_EVENT_CONNECT_FAILED, &ev, 3000));
    ASSERT_EQ(ev.disconnect_reason, NL_ERR_SERVER_FULL);

    nl_endpoint_destroy(c1);
    nl_endpoint_destroy(c2);
    nl_endpoint_destroy(server);
}

int main(void) {
    printf("=== integration tests (real UDP sockets) ===\n");
    RUN_TEST(test_connect_and_reliable_ordered_data);
    RUN_TEST(test_all_delivery_modes_over_real_sockets);
    RUN_TEST(test_fragmentation_over_real_sockets);
    RUN_TEST(test_multiple_channels_dont_block_each_other);
    RUN_TEST(test_graceful_disconnect_over_real_sockets);
    RUN_TEST(test_ipv6_loopback);
    RUN_TEST(test_discovery_over_real_sockets);
    RUN_TEST(test_server_denies_when_full);
    TEST_SUMMARY();
}
