#include "../include/netlink.h"
#include <string.h>

const char *nl_version_string(void) {
    return "0.1.0";
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
    memset(cfg, 0, sizeof(*cfg));
    cfg->transport = NL_TRANSPORT_UDP;
    cfg->family = NL_AF_UNSPEC;
    cfg->channel_count = 4;
    cfg->max_connections = 64;
    cfg->connection_timeout_ms = 10000;
    cfg->keepalive_interval_ms = 1000;
    cfg->encryption_enabled = true;
    cfg->server_name = NULL;
}
