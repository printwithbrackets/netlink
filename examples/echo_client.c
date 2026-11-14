/* echo_client.c - connects to the echo server, sends a few messages
 * across different channels and delivery modes, and prints the echoes. */
#define _POSIX_C_SOURCE 200809L /* clock_gettime under -std=c11 */
#include <weft_net.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint16_t parse_port(const char *s, uint16_t dflt) {
    if (!s) return dflt;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || v > 65535) {
        fprintf(stderr, "invalid port '%s', using %u\n", s, dflt);
        return dflt;
    }
    return (uint16_t)v;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    uint16_t port = argc > 2 ? parse_port(argv[2], 9000) : 9000;

    wn_config_t cfg;
    wn_config_default(&cfg);

    wn_endpoint_t *client = NULL;
    wn_result_t r = wn_client_create(&cfg, &client);
    if (r != WN_OK) {
        fprintf(stderr, "failed to create client: %s\n", wn_error_string(r));
        return 1;
    }

    wn_address_t server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    if (snprintf(server_addr.host, sizeof(server_addr.host), "%s", host) >= (int)sizeof(server_addr.host)) {
        fprintf(stderr, "host name too long (max %zu bytes)\n", sizeof(server_addr.host) - 1);
        wn_endpoint_destroy(client);
        return 1;
    }
    server_addr.port = port;
    server_addr.family = WN_AF_UNSPEC;

    wn_peer_id_t server;
    r = wn_connect(client, &server_addr, &server);
    if (r != WN_OK) {
        fprintf(stderr, "connect failed: %s\n", wn_error_string(r));
        return 1;
    }

    printf("Connecting to %s:%u ...\n", host, port);

    bool connected = false;
    bool sent_batch = false;
    int echoes_received = 0;
    const int total_messages = 3;
    int exit_code = 0;
    /* Deadlines are measured from a fixed start, not per poll: one quiet
     * 500 ms poll says nothing, the handshake retries every 250 ms and a
     * lossy link can need several rounds. */
    const uint64_t connect_deadline_ms = now_ms() + 5000;
    uint64_t echo_deadline_ms = 0;

    while (1) {
        wn_event_t ev;
        if (!wn_poll_event(client, &ev, 500)) {
            if (!connected && now_ms() > connect_deadline_ms) {
                fprintf(stderr, "timed out waiting to connect\n");
                exit_code = 1;
                break;
            }
            if (sent_batch && now_ms() > echo_deadline_ms) {
                /* The UNRELIABLE_SEQUENCED echo may legitimately be dropped, so
                 * waiting for all three forever would hang on a lossy link. */
                fprintf(stderr, "gave up after %d of %d echoes\n", echoes_received, total_messages);
                exit_code = echoes_received >= total_messages - 1 ? 0 : 1;
                break;
            }
            continue;
        }

        switch (ev.event_type) {
            case WN_EVENT_CONNECTED:
                printf("Connected! (peer id %llu)\n", (unsigned long long)ev.peer);
                connected = true;
                break;
            case WN_EVENT_CONNECT_FAILED:
                fprintf(stderr, "connection failed: %s\n", wn_error_string(ev.disconnect_reason));
                wn_endpoint_destroy(client);
                return 1;
            case WN_EVENT_DATA:
                printf("Echo received on channel %u: ", ev.channel);
                if (ev.data_len > 0 && ev.data) fwrite(ev.data, 1, ev.data_len, stdout);
                printf("\n");
                echoes_received++;
                if (echoes_received >= total_messages) {
                    wn_disconnect(client, server);
                    wn_endpoint_destroy(client);
                    return 0;
                }
                break;
            case WN_EVENT_DISCONNECTED:
                printf("Disconnected: %s\n", wn_error_string(ev.disconnect_reason));
                wn_endpoint_destroy(client);
                return 0;
            default:
                break;
        }

        if (connected && !sent_batch) {
            sent_batch = true;
            echo_deadline_ms = now_ms() + 5000;
            wn_send(client, server, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"hello reliable", 14);
            wn_send(client, server, 1, WN_UNRELIABLE_SEQUENCED, (const uint8_t *)"hello sequenced", 15);
            wn_send(client, server, 2, WN_RELIABLE_UNORDERED, (const uint8_t *)"hello unordered", 15);
        }
    }

    wn_endpoint_destroy(client);
    return exit_code;
}
