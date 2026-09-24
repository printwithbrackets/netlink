/* Integration tests for NL_TRANSPORT_WEBSOCKET: real client + server over
 * loopback TCP, HTTP upgrade (RFC6455), then the normal encrypted NetLink
 * handshake and delivery modes inside binary WebSocket frames. */
#include "../test_framework.h"
#include "../../include/netlink.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static bool wait_for_event(nl_endpoint_t *ep, nl_event_type_t type, nl_event_t *out, int timeout_ms) {
    uint64_t iterations = (uint64_t)timeout_ms / 50 + 1;
    for (uint64_t i = 0; i < iterations; i++) {
        if (nl_poll_event(ep, out, 50)) {
            if (out->event_type == type) return true;
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

static void ws_config(nl_config_t *cfg) {
    nl_config_default(cfg);
    cfg->transport = NL_TRANSPORT_WEBSOCKET;
}

TEST(test_ws_connect_and_reliable_echo) {
    nl_config_t cfg; ws_config(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34751);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);

    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 5000));
    nl_peer_id_t server_peer = ev.peer;

    const char *msg = "websocket hello";
    ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED,
                      (const uint8_t *)msg, strlen(msg)), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.data_len, strlen(msg));
    ASSERT_MEM_EQ(ev.data, msg, strlen(msg));

    const char *reply = "echo from ws server";
    ASSERT_EQ(nl_send(server, server_peer, 0, NL_RELIABLE_ORDERED,
                      (const uint8_t *)reply, strlen(reply)), NL_OK);
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.data_len, strlen(reply));
    ASSERT_MEM_EQ(ev.data, reply, strlen(reply));

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_ws_unreliable_delivery) {
    nl_config_t cfg; ws_config(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34752);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 5000));

    const uint8_t payload[] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(nl_send(client, client_peer, 2, NL_UNRELIABLE, payload, sizeof(payload)), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.channel, 2);
    ASSERT_EQ(ev.data_len, sizeof(payload));
    ASSERT_MEM_EQ(ev.data, payload, sizeof(payload));

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_ws_fragmented_large_message) {
    nl_config_t cfg; ws_config(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34753);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 5000));

    size_t big_len = 5000;
    uint8_t *big = (uint8_t *)malloc(big_len);
    ASSERT_TRUE(big != NULL);
    for (size_t i = 0; i < big_len; i++) big[i] = (uint8_t)((i * 13 + 7) & 0xFF);

    ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, big, big_len), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 10000));
    ASSERT_EQ(ev.data_len, big_len);
    ASSERT_MEM_EQ(ev.data, big, big_len);

    free(big);
    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

TEST(test_ws_discovery_unsupported) {
    nl_config_t cfg; ws_config(&cfg);
    nl_endpoint_t *server = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34754);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_discovery_enable(server, 34999), NL_ERR_UNSUPPORTED);
    nl_endpoint_destroy(server);

    nl_endpoint_t *client = NULL;
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);
    ASSERT_EQ(nl_discovery_probe(client, 34999, 100), NL_ERR_UNSUPPORTED);
    nl_endpoint_destroy(client);
}

TEST(test_ws_rejects_cleartext_config) {
    nl_config_t cfg; ws_config(&cfg);
    cfg.encryption_enabled = false;
    nl_endpoint_t *ep = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34755);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &ep), NL_ERR_UNSUPPORTED);
    ASSERT_EQ(nl_client_create(&cfg, &ep), NL_ERR_UNSUPPORTED);
}

int main(void) {
    printf("websocket integration tests\n");
    RUN_TEST(test_ws_connect_and_reliable_echo);
    RUN_TEST(test_ws_unreliable_delivery);
    RUN_TEST(test_ws_fragmented_large_message);
    RUN_TEST(test_ws_discovery_unsupported);
    RUN_TEST(test_ws_rejects_cleartext_config);
    TEST_SUMMARY();
}
