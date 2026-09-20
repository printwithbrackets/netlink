/* echo_server.c - minimal example: accepts connections and echoes back
 * whatever it receives on any channel, using the same delivery mode it
 * was sent with. Build: make examples (or see README for a manual gcc line). */
#include <netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

int main(int argc, char **argv) {
    uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 9000;

    setvbuf(stdout, NULL, _IOLBF, 0); /* line-buffer even when redirected, so logs show up promptly */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    nl_config_t cfg;
    nl_config_default(&cfg);
    cfg.server_name = "NetLink Example Server";

    nl_address_t bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    strncpy(bind_addr.host, "0.0.0.0", sizeof(bind_addr.host) - 1);
    bind_addr.port = port;
    bind_addr.family = NL_AF_INET;

    nl_endpoint_t *server = NULL;
    nl_result_t r = nl_server_create(&bind_addr, &cfg, &server);
    if (r != NL_OK) {
        fprintf(stderr, "failed to start server: %s\n", nl_error_string(r));
        return 1;
    }
    nl_discovery_enable(server, (uint16_t)(port + 1));

    printf("NetLink echo server listening on UDP port %u (discovery on %u)\n", port, port + 1);
    printf("Press Ctrl+C to stop.\n");

    while (!g_stop) {
        nl_event_t ev;
        if (!nl_poll_event(server, &ev, 200)) continue;

        switch (ev.type) {
            case NL_EVENT_CONNECTED:
                printf("[+] peer %llu connected from %s:%u\n",
                       (unsigned long long)ev.peer, ev.from_address.host, ev.from_address.port);
                break;
            case NL_EVENT_DISCONNECTED:
                printf("[-] peer %llu disconnected (%s)\n",
                       (unsigned long long)ev.peer, nl_error_string(ev.disconnect_reason));
                break;
            case NL_EVENT_DATA:
                printf("[.] echoing %zu bytes from peer %llu on channel %u\n",
                       ev.data_len, (unsigned long long)ev.peer, ev.channel);
                /* Echo back reliably-ordered regardless of how it arrived,
                 * for simplicity; a real app would usually mirror the
                 * original delivery mode. */
                nl_send(server, ev.peer, ev.channel, NL_RELIABLE_ORDERED, ev.data, ev.data_len);
                break;
            default:
                break;
        }
    }

    printf("\nShutting down.\n");
    nl_endpoint_destroy(server);
    return 0;
}
