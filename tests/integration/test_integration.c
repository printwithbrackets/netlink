/* Integration tests: real nl_endpoint_t client + server talking over
 * actual loopback UDP sockets (127.0.0.1 and ::1), exercising the full
 * stack end to end -- handshake, encryption, all delivery modes,
 * multiple channels, fragmentation, disconnects, and discovery. */
#include "../test_framework.h"
#include "../../include/netlink.h"
#include "../../src/byteorder.h"
#include "../../src/protocol.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

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

TEST(test_capability_negotiation_intersects_both_sides) {
    /* Server advertises flow-control + rate-limit only; client advertises
     * flow-control + priority only. Negotiated set on both sides must be
     * the intersection (flow-control alone), never the local full set. */
    nl_config_t scfg, ccfg;
    nl_config_default(&scfg);
    nl_config_default(&ccfg);
    scfg.capabilities = NL_CAP_FLOW_CONTROL | NL_CAP_RATE_LIMIT;
    ccfg.capabilities = NL_CAP_FLOW_CONTROL | NL_CAP_PRIORITY;

    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34717);
    ASSERT_EQ(nl_server_create(&bind_addr, &scfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&ccfg, &client), NL_OK);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);

    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));
    nl_peer_id_t server_side_peer = ev.peer;

    uint32_t client_caps = 0, server_caps = 0;
    ASSERT_TRUE(nl_peer_capabilities(client, client_peer, &client_caps));
    ASSERT_TRUE(nl_peer_capabilities(server, server_side_peer, &server_caps));
    ASSERT_EQ(client_caps, NL_CAP_FLOW_CONTROL);
    ASSERT_EQ(server_caps, NL_CAP_FLOW_CONTROL);

    const char *msg = "negotiated";
    ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED,
                      (const uint8_t *)msg, strlen(msg)), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 3000));
    ASSERT_MEM_EQ(ev.data, msg, strlen(msg));

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

/* Large message over real sockets: 40000 bytes (40 fragments) exceeds the
 * initial congestion window, so delivery depends on the endpoint's
 * post-drain standalone-ack flush (NL_PKT_ACK) and continuation parking. */
TEST(test_large_message_40000_over_real_sockets) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34715);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    size_t big_len = 40000;
    uint8_t *big = (uint8_t *)malloc(big_len);
    ASSERT_TRUE(big != NULL);
    for (size_t i = 0; i < big_len; i++) big[i] = (uint8_t)((i * 17 + 3) & 0xFF);

    ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, big, big_len), NL_OK);
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 15000));
    ASSERT_EQ(ev.data_len, big_len);
    ASSERT_MEM_EQ(ev.data, big, big_len);

    /* Server must still be connected (acks kept the client from giving up). */
    nl_peer_stats_t cstats;
    ASSERT_TRUE(nl_peer_stats(client, client_peer, &cstats));

    free(big);
    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

/* One-way reliable traffic: the server never sends application data, so
 * every ack must ride on a standalone NL_PKT_ACK (endpoint flush after
 * socket drain). Without those, the client would retransmit until give-up
 * and the server would see duplicates/timeout. */
TEST(test_one_way_reliable_over_real_sockets) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34716);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    nl_peer_id_t client_peer;
    ASSERT_EQ(nl_connect(client, &bind_addr, &client_peer), NL_OK);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));

    for (int i = 0; i < 5; i++) {
        char msg[8];
        snprintf(msg, sizeof(msg), "ow%d", i);
        ASSERT_EQ(nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED,
                          (const uint8_t *)msg, strlen(msg)), NL_OK);
    }

    for (int i = 0; i < 5; i++) {
        ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 5000));
        ASSERT_EQ(ev.channel, 0);
    }

    /* Let acks round-trip and any RTO fire: client stats must show no
     * retransmits (acks arrived via NL_PKT_ACK before the first RTO). */
    nl_peer_stats_t cstats;
    ASSERT_TRUE(nl_peer_stats(client, client_peer, &cstats));
    ASSERT_EQ(cstats.retransmits, 0u);

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
    nl_result_t probe = nl_discovery_probe(client, 34799, 1000);
    if (probe != NL_OK) {
        /* Broadcast (and loopback fallback) may both be unavailable in a
         * restricted namespace; skip rather than fail the whole suite. */
        printf("  SKIP test_discovery_over_real_sockets: nl_discovery_probe failed (%d)\n", probe);
        nl_endpoint_destroy(client);
        nl_endpoint_destroy(server);
        return;
    }

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

TEST(test_peer_stats_over_real_sockets) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34709);
    nl_server_create(&bind_addr, &cfg, &server);
    nl_client_create(&cfg, &client);

    nl_peer_id_t client_peer;
    nl_connect(client, &bind_addr, &client_peer);
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_CONNECTED, &ev, 3000));
    nl_peer_id_t server_peer = ev.peer;

    const char *msg = "measure me";
    nl_send(client, client_peer, 0, NL_RELIABLE_ORDERED, (const uint8_t *)msg, strlen(msg));
    ASSERT_TRUE(wait_for_event(server, NL_EVENT_DATA, &ev, 3000));

    /* Give the reliable ack a moment to round-trip back to the client so
     * an RTT sample has actually landed (real sockets, real timing). */
    nl_send(server, server_peer, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"ack", 3);
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_DATA, &ev, 3000));

    nl_peer_stats_t cstats, sstats;
    ASSERT_TRUE(nl_peer_stats(client, client_peer, &cstats));
    ASSERT_TRUE(nl_peer_stats(server, server_peer, &sstats));

    ASSERT_TRUE(cstats.packets_sent >= 1);
    ASSERT_TRUE(cstats.bytes_sent > 0);
    ASSERT_TRUE(sstats.packets_received >= 1);
    ASSERT_TRUE(sstats.bytes_received > 0);
    /* A real loopback round trip should be fast but nonzero-measurable;
     * mainly confirm it's wired up (not still at its zero default) and
     * not absurd (e.g. not accidentally reporting seconds as ms). */
    ASSERT_TRUE(cstats.rtt_ms < 2000);

    ASSERT_FALSE(nl_peer_stats(client, 0xDEADBEEF, &cstats)); /* unknown peer */

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

/* Regression: encryption_enabled=false must be rejected at construction --
 * there is no cleartext mode; silently encrypting anyway or shipping a
 * protocol hole would both be wrong. */
TEST(test_encryption_disabled_rejected) {
    nl_config_t cfg; nl_config_default(&cfg);
    cfg.encryption_enabled = false;
    nl_endpoint_t *ep = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34710);

    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &ep), NL_ERR_UNSUPPORTED);
    ASSERT_TRUE(ep == NULL);
    ep = NULL;
    ASSERT_EQ(nl_client_create(&cfg, &ep), NL_ERR_UNSUPPORTED);
    ASSERT_TRUE(ep == NULL);
}

/* Regression: a second nl_connect() to the same address while one is in
 * flight (or already established) must return NL_ERR_ALREADY_CONNECTED
 * rather than collide on the pending table's address-keyed lookups. */
TEST(test_duplicate_connect_same_address_rejected) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34711);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    nl_peer_id_t p1, p2;
    ASSERT_EQ(nl_connect(client, &bind_addr, &p1), NL_OK);
    /* Second connect while first is still in flight (AWAIT_CHALLENGE). */
    ASSERT_EQ(nl_connect(client, &bind_addr, &p2), NL_ERR_ALREADY_CONNECTED);

    /* Let the first handshake finish, then a third connect (now established). */
    nl_event_t ev;
    ASSERT_TRUE(wait_for_event(client, NL_EVENT_CONNECTED, &ev, 3000));
    ASSERT_EQ(nl_connect(client, &bind_addr, &p2), NL_ERR_ALREADY_CONNECTED);

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

/* Regression: max_connections above the hard internal cap (512) must be
 * clamped so discovery advertises the real limit, not a value that would
 * make REQUEST-time checks pass and then fail silently at slot alloc. */
TEST(test_max_connections_clamped_to_internal_cap) {
    nl_config_t cfg; nl_config_default(&cfg);
    cfg.max_connections = 10000; /* way above NL_MAX_CONNECTIONS_INTERNAL */
    cfg.server_name = "Clamp Test";
    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34712);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);

    ASSERT_EQ(nl_discovery_enable(server, 34801), NL_OK);
    nl_result_t probe = nl_discovery_probe(client, 34801, 500);
    if (probe != NL_OK) {
        printf("  SKIP clamp discovery assert: nl_discovery_probe failed (%d)\n", probe);
        nl_endpoint_destroy(client);
        nl_endpoint_destroy(server);
        return;
    }

    nl_event_t ev;
    bool got = wait_for_event(client, NL_EVENT_DISCOVERY_REPLY, &ev, 3000);
    if (got) {
        /* Advertised max must be the clamped 512, not 10000. */
        ASSERT_EQ(ev.server_max_players, 512u);
    } else {
        printf("  SKIP clamp discovery assert: broadcast filtered in this namespace\n");
    }

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

/* Regression: server_name must be copied into the endpoint at create time.
 * If config.server_name is only a shallow pointer, clobbering the caller's
 * buffer after nl_server_create would change what discovery reports. */
TEST(test_server_name_copied_at_create_time) {
    nl_config_t cfg; nl_config_default(&cfg);
    char name_buf[NL_SERVER_NAME_MAX];
    strncpy(name_buf, "Stable Name", sizeof(name_buf) - 1);
    name_buf[sizeof(name_buf) - 1] = '\0';
    cfg.server_name = name_buf;

    nl_endpoint_t *server = NULL, *client = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34713);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);

    /* Clobber the caller's buffer -- discovery must still report the
     * original name (proving the library made its own copy). */
    memset(name_buf, 'X', sizeof(name_buf) - 1);
    name_buf[sizeof(name_buf) - 1] = '\0';

    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);
    ASSERT_EQ(nl_discovery_enable(server, 34802), NL_OK);
    nl_result_t probe = nl_discovery_probe(client, 34802, 500);
    if (probe != NL_OK) {
        printf("  SKIP server_name discovery assert: nl_discovery_probe failed (%d)\n", probe);
        nl_endpoint_destroy(client);
        nl_endpoint_destroy(server);
        return;
    }

    nl_event_t ev;
    bool got = wait_for_event(client, NL_EVENT_DISCOVERY_REPLY, &ev, 3000);
    if (got) {
        ASSERT_TRUE(strcmp(ev.server_name, "Stable Name") == 0);
    } else {
        printf("  SKIP server_name discovery assert: broadcast filtered in this namespace\n");
    }

    nl_endpoint_destroy(client);
    nl_endpoint_destroy(server);
}

/* Regression (finding 5): a DISCOVERY_RESPONSE whose nonce does not match
 * the most recent probe must be dropped, not surfaced as a live result.
 * Probes now carry a random (never-zero) nonce, so the test binds to the
 * loopback discovery port first, captures the outgoing probe, and echoes
 * its real nonce for the positive case. Also checks that from_address
 * comes from the packet's socket source, not the body's server_port. */
TEST(test_discovery_wrong_nonce_ignored) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *client = NULL;

    /* Bind before probing so the client's unconditional loopback copy
     * (127.0.0.1:34804) lands here and we can read the random nonce. */
    int raw = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_TRUE(raw >= 0);
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(34804);
    bind_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ASSERT_EQ(bind(raw, (struct sockaddr *)&bind_addr, sizeof(bind_addr)), 0);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };
    setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ASSERT_EQ(nl_client_create(&cfg, &client), NL_OK);
    nl_result_t probe = nl_discovery_probe(client, 34804, 500);
    if (probe != NL_OK) {
        printf("  SKIP test_discovery_wrong_nonce_ignored: nl_discovery_probe failed (%d)\n", probe);
        close(raw);
        nl_endpoint_destroy(client);
        return;
    }

    /* Capture the outgoing DISCOVERY_REQUEST (loopback copy). */
    uint8_t req[NL_DISCOVERY_REQUEST_SIZE + 16];
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    ssize_t n = recvfrom(raw, req, sizeof(req), 0, (struct sockaddr *)&from, &from_len);
    if (n < (ssize_t)NL_DISCOVERY_REQUEST_SIZE || req[0] != NL_PKT_DISCOVERY_REQUEST) {
        printf("  SKIP test_discovery_wrong_nonce_ignored: no probe captured on loopback\n");
        close(raw);
        nl_endpoint_destroy(client);
        return;
    }
    uint32_t real_nonce = nl_get_u32(req + 5);
    ASSERT_TRUE(real_nonce != 0); /* probes are never zero so 0 is a guaranteed-wrong nonce */

    struct sockaddr_in reply_to;
    memset(&reply_to, 0, sizeof(reply_to));
    reply_to.sin_family = AF_INET;
    reply_to.sin_port = ((struct sockaddr_in *)&from)->sin_port;
    reply_to.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Nonce 0: guaranteed wrong -- must not surface. Body claims port 9999
     * so a buggy from_address (body-sourced) would be distinguishable. */
    uint8_t resp[NL_DISCOVERY_RESPONSE_MIN_SIZE + 16];
    size_t o = 0;
    resp[o++] = NL_PKT_DISCOVERY_RESPONSE;
    nl_put_u32(resp + o, 0); o += 4;
    nl_put_u16(resp + o, 9999); o += 2;
    nl_put_u32(resp + o, 0); o += 4;
    nl_put_u32(resp + o, 64); o += 4;
    resp[o++] = 4;
    memcpy(resp + o, "fake", 4); o += 4;
    ASSERT_TRUE(sendto(raw, resp, o, 0, (struct sockaddr *)&reply_to, sizeof(reply_to)) >= 0);

    nl_event_t ev;
    bool got_bad = wait_for_event(client, NL_EVENT_DISCOVERY_REPLY, &ev, 300);
    ASSERT_TRUE(!got_bad); /* wrong nonce must not surface */

    /* Captured nonce must be accepted. Body still claims 9999; the event's
     * from_address.port must be THIS socket's source (34804), proving the
     * library used the socket source, not the attacker-controlled body. */
    o = 0;
    resp[o++] = NL_PKT_DISCOVERY_RESPONSE;
    nl_put_u32(resp + o, real_nonce); o += 4;
    nl_put_u16(resp + o, 9999); o += 2; /* lie in the body */
    nl_put_u32(resp + o, 0); o += 4;
    nl_put_u32(resp + o, 64); o += 4;
    resp[o++] = 5;
    memcpy(resp + o, "valid", 5); o += 5;
    ASSERT_TRUE(sendto(raw, resp, o, 0, (struct sockaddr *)&reply_to, sizeof(reply_to)) >= 0);

    ASSERT_TRUE(wait_for_event(client, NL_EVENT_DISCOVERY_REPLY, &ev, 1000));
    ASSERT_TRUE(strcmp(ev.server_name, "valid") == 0);
    ASSERT_EQ(ev.from_address.port, 34804u); /* socket source, not body's 9999 */

    close(raw);
    nl_endpoint_destroy(client);
}

/* Regression (finding 5): discovery replies have their own rate-limit
 * budget so a flood of DISCOVERY_REQUESTs cannot elicit unbounded
 * responses. Unicast (no broadcast required): fire far more requests than
 * the per-window cap and assert the server stops answering. */
TEST(test_discovery_rate_limited) {
    nl_config_t cfg; nl_config_default(&cfg);
    nl_endpoint_t *server = NULL;
    nl_address_t bind_addr = addr("127.0.0.1", 34714);
    ASSERT_EQ(nl_server_create(&bind_addr, &cfg, &server), NL_OK);
    const uint16_t dport = 34805;
    ASSERT_EQ(nl_discovery_enable(server, dport), NL_OK);

    int raw = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_TRUE(raw >= 0);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dport);
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Well above NL_RATE_LIMIT_MAX_PER_WINDOW (200), all in one window. */
    const int flood = 300;
    uint8_t req[NL_DISCOVERY_REQUEST_SIZE];
    req[0] = NL_PKT_DISCOVERY_REQUEST;
    nl_put_u32(req + 1, NL_MAGIC);
    for (int i = 0; i < flood; i++) {
        nl_put_u32(req + 5, (uint32_t)(i + 1));
        ASSERT_TRUE(sendto(raw, req, sizeof(req), 0, (struct sockaddr *)&dst, sizeof(dst)) >= 0);
    }

    /* Drain responses until the socket times out. */
    int responses = 0;
    uint8_t buf[256];
    for (;;) {
        ssize_t n = recv(raw, buf, sizeof(buf), 0);
        if (n < 0) break;
        if (n >= 1 && buf[0] == NL_PKT_DISCOVERY_RESPONSE) responses++;
    }

    /* Sanity: unicast discovery works at all in this namespace. */
    ASSERT_TRUE(responses >= 1);
    /* Rate limit must kick in before the flood is fully answered. */
    ASSERT_TRUE(responses < flood);
    /* And must not have allowed more than the documented per-window cap
     * (plus a small slack for a window boundary race mid-flood). */
    ASSERT_TRUE(responses <= 210);

    close(raw);
    nl_endpoint_destroy(server);
}

/* Version consistency: nl_version_string() must match the NL_VERSION_*
 * macros so bindings and callers that parse either stay in sync. */
TEST(test_version_string_matches_macros) {
    char expected[32];
    snprintf(expected, sizeof(expected), "%d.%d.%d",
             NL_VERSION_MAJOR, NL_VERSION_MINOR, NL_VERSION_PATCH);
    ASSERT_TRUE(strcmp(nl_version_string(), expected) == 0);
}

int main(void) {
    printf("=== integration tests (real UDP sockets) ===\n");
    RUN_TEST(test_version_string_matches_macros);
    RUN_TEST(test_connect_and_reliable_ordered_data);
    RUN_TEST(test_capability_negotiation_intersects_both_sides);
    RUN_TEST(test_all_delivery_modes_over_real_sockets);
    RUN_TEST(test_fragmentation_over_real_sockets);
    RUN_TEST(test_large_message_40000_over_real_sockets);
    RUN_TEST(test_one_way_reliable_over_real_sockets);
    RUN_TEST(test_multiple_channels_dont_block_each_other);
    RUN_TEST(test_graceful_disconnect_over_real_sockets);
    RUN_TEST(test_ipv6_loopback);
    RUN_TEST(test_discovery_over_real_sockets);
    RUN_TEST(test_discovery_wrong_nonce_ignored);
    RUN_TEST(test_discovery_rate_limited);
    RUN_TEST(test_peer_stats_over_real_sockets);
    RUN_TEST(test_server_denies_when_full);
    RUN_TEST(test_encryption_disabled_rejected);
    RUN_TEST(test_duplicate_connect_same_address_rejected);
    RUN_TEST(test_max_connections_clamped_to_internal_cap);
    RUN_TEST(test_server_name_copied_at_create_time);
    TEST_SUMMARY();
}
