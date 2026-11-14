#include "../include/weft_net.h"
#include <string.h>

#define WN_STR_(x) #x
#define WN_STR(x) WN_STR_(x)

const char *wn_version_string(void) {
    /* Built from the WN_VERSION_* macros so the string can never drift
     * from the header (see test_version_string_matches_macros). */
    static const char ver[] = WN_STR(WN_VERSION_MAJOR) "."
                              WN_STR(WN_VERSION_MINOR) "."
                              WN_STR(WN_VERSION_PATCH);
    return ver;
}

const char *wn_error_string(wn_result_t code) {
    switch (code) {
        case WN_OK: return "ok";
        case WN_ERR_INVALID_ARGUMENT: return "invalid argument";
        case WN_ERR_OUT_OF_MEMORY: return "out of memory";
        case WN_ERR_SOCKET: return "socket error";
        case WN_ERR_BIND_FAILED: return "bind failed";
        case WN_ERR_NOT_CONNECTED: return "not connected";
        case WN_ERR_ALREADY_CONNECTED: return "already connected";
        case WN_ERR_MESSAGE_TOO_LARGE: return "message too large";
        case WN_ERR_CHANNEL_OUT_OF_RANGE: return "channel out of range";
        case WN_ERR_QUEUE_FULL: return "queue full";
        case WN_ERR_CRYPTO: return "cryptographic operation failed";
        case WN_ERR_PROTOCOL_MISMATCH: return "protocol mismatch";
        case WN_ERR_TIMEOUT: return "timeout";
        case WN_ERR_PEER_NOT_FOUND: return "peer not found";
        case WN_ERR_DENIED: return "connection denied";
        case WN_ERR_UNSUPPORTED: return "unsupported";
        case WN_ERR_SERVER_FULL: return "server full";
        case WN_ERR_INTERNAL: return "internal error";
        default: return "unknown error";
    }
}

void wn_config_default(wn_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->transport = WN_TRANSPORT_UDP;
    cfg->family = WN_AF_UNSPEC;
    cfg->channel_count = 4;
    cfg->max_connections = 64;
    cfg->connection_timeout_ms = 10000;
    cfg->keepalive_interval_ms = 1000;
    cfg->encryption_enabled = true;
    cfg->server_name = NULL;
    cfg->max_send_bytes_per_sec = 0; /* unlimited */
    cfg->recv_window_bytes = 32768;
    cfg->event_queue_max_bytes = WN_EVENT_QUEUE_MAX_BYTES_DEFAULT;
    cfg->capabilities = WN_CAP_DEFAULT;
}
