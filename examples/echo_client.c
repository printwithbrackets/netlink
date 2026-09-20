/* echo_client.c - connects to the echo server, sends a few messages
 * across different channels and delivery modes, and prints the echoes. */
#include <netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 9000;

    nl_config_t cfg;
    nl_config_default(&cfg);

    nl_endpoint_t *client = NULL;
    nl_result_t r = nl_client_create(&cfg, &client);
    if (r != NL_OK) {
        fprintf(stderr, "failed to create client: %s\n", nl_error_string(r));
        return 1;
    }

    nl_address_t server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    strncpy(server_addr.host, host, sizeof(server_addr.host) - 1);
    server_addr.port = port;
    server_addr.family = NL_AF_UNSPEC;

    nl_peer_id_t server;
    r = nl_connect(client, &server_addr, &server);
    if (r != NL_OK) {
        fprintf(stderr, "connect failed: %s\n", nl_error_string(r));
        return 1;
    }

    printf("Connecting to %s:%u ...\n", host, port);

    bool connected = false;
    bool sent_batch = false;
    int echoes_received = 0;
    const int total_messages = 3;

    while (1) {
        nl_event_t ev;
        if (!nl_poll_event(client, &ev, 500)) {
            if (!connected) {
                fprintf(stderr, "timed out waiting to connect\n");
                break;
            }
            continue;
        }

        switch (ev.type) {
            case NL_EVENT_CONNECTED:
                printf("Connected! (peer id %llu)\n", (unsigned long long)ev.peer);
                connected = true;
                break;
            case NL_EVENT_CONNECT_FAILED:
                fprintf(stderr, "connection failed: %s\n", nl_error_string(ev.disconnect_reason));
                nl_endpoint_destroy(client);
                return 1;
            case NL_EVENT_DATA:
                printf("Echo received on channel %u: %.*s\n", ev.channel, (int)ev.data_len, (const char *)ev.data);
                echoes_received++;
                if (echoes_received >= total_messages) {
                    nl_disconnect(client, server);
                    nl_endpoint_destroy(client);
                    return 0;
                }
                break;
            case NL_EVENT_DISCONNECTED:
                printf("Disconnected: %s\n", nl_error_string(ev.disconnect_reason));
                nl_endpoint_destroy(client);
                return 0;
            default:
                break;
        }

        if (connected && !sent_batch) {
            sent_batch = true;
            nl_send(client, server, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"hello reliable", 14);
            nl_send(client, server, 1, NL_UNRELIABLE_SEQUENCED, (const uint8_t *)"hello sequenced", 15);
            nl_send(client, server, 2, NL_RELIABLE_UNORDERED, (const uint8_t *)"hello unordered", 15);
        }
    }

    nl_endpoint_destroy(client);
    return 0;
}
