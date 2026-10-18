#include "../include/netlink.h"
#include <string.h>

#define NL_STR_(x) #x
#define NL_STR(x) NL_STR_(x)

const char *nl_version_string(void) {
    /* Built from the NL_VERSION_* macros so the string can never drift
     * from the header (see test_version_string_matches_macros). */
    static const char ver[] = NL_STR(NL_VERSION_MAJOR) "."
                              NL_STR(NL_VERSION_MINOR) "."
                              NL_STR(NL_VERSION_PATCH);
    return ver;
}

const char *nl_error_string(nl_result_t code) {
    switch (code) {
        case NL_OK: return "ok";
        case NL_ERR_INVALID_ARGUMENT: return "invalid argument";
        case NL_ERR_OUT_OF_MEMORY: return "out of memory";
        case NL_ERR_SOCKET: return "socket error";
        case NL_ERR_BIND_FAILED: return "bind failed";
        case NL_ERR_NOT_CONNECTED: return "not connected";
        case NL_ERR_ALREADY_CONNECTED: return "already connected";
        case NL_ERR_MESSAGE_TOO_LARGE: return "message too large";
        case NL_ERR_CHANNEL_OUT_OF_RANGE: return "channel out of range";
        case NL_ERR_QUEUE_FULL: return "queue full";
        case NL_ERR_CRYPTO: return "cryptographic operation failed";
        case NL_ERR_PROTOCOL_MISMATCH: return "protocol mismatch";
        case NL_ERR_TIMEOUT: return "timeout";
        case NL_ERR_PEER_NOT_FOUND: return "peer not found";
        case NL_ERR_DENIED: return "connection denied";
        case NL_ERR_UNSUPPORTED: return "unsupported";
        case NL_ERR_SERVER_FULL: return "server full";
        case NL_ERR_INTERNAL: return "internal error";
        default: return "unknown error";
    }
}

void nl_config_default(nl_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->transport = NL_TRANSPORT_UDP;
    cfg->family = NL_AF_UNSPEC;
    cfg->channel_count = 4;
    cfg->max_connections = 64;
    cfg->connection_timeout_ms = 10000;
    cfg->keepalive_interval_ms = 1000;
    cfg->encryption_enabled = true;
    cfg->server_name = NULL;
    cfg->max_send_bytes_per_sec = 0; /* unlimited */
    cfg->recv_window_bytes = 32768;
    cfg->event_queue_max_bytes = NL_EVENT_QUEUE_MAX_BYTES_DEFAULT;
    cfg->capabilities = NL_CAP_DEFAULT;
}
