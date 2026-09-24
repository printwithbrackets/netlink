#include "websocket.h"
#include "crypto.h"
#include "byteorder.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ---- base64 / SHA-1 (OpenSSL EVP only; see CONTRIBUTING.md) ---- */

bool nl_ws_base64_encode(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return false;
    if (len > (SIZE_MAX / 4) * 3) return false;
    int need = (int)(((len + 2) / 3) * 4);
    if (need < 0 || (size_t)need + 1 > out_cap) return false;
    if (EVP_EncodeBlock((unsigned char *)out, data, (int)len) < 0) return false;
    out[need] = '\0';
    return true;
}

bool nl_ws_base64_sha1(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    uint8_t digest[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) == 1 &&
              EVP_DigestUpdate(ctx, data, len) == 1 &&
              EVP_DigestFinal_ex(ctx, digest, NULL) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) return false;
    return nl_ws_base64_encode(digest, sizeof(digest), out, out_cap);
}

/* ---- frame encode ---- */

size_t nl_ws_frame_size(size_t payload_len, bool mask) {
    size_t header;
    if (payload_len < 126) header = 2;
    else if (payload_len <= 0xFFFF) header = 4;
    else if (payload_len <= 0x7FFFFFFFFFFFFFFFULL) header = 10;
    else return 0;
    if (payload_len > NL_WS_MAX_MESSAGE) return 0;
    if (mask) header += 4;
    if (header > SIZE_MAX - payload_len) return 0;
    return header + payload_len;
}

size_t nl_ws_encode(uint8_t opcode, const uint8_t *payload, size_t payload_len,
                    bool mask, uint8_t *out, size_t out_cap) {
    if (!out) return 0;
    if (opcode > 0xF) return 0;
    /* Control frames must be FIN and <= 125 (RFC 6455 §5.5). */
    if (opcode >= 0x8) {
        if (payload_len > 125) return 0;
        /* caller sets FIN in the opcode byte via 0x80 below; non-FIN
         * control frames are rejected at encode time by requiring the
         * high bit pattern we always set. */
    }
    size_t need = nl_ws_frame_size(payload_len, mask);
    if (need == 0 || need > out_cap) return 0;

    size_t o = 0;
    out[o++] = (uint8_t)(0x80 | (opcode & 0x0F)); /* FIN always set on frames we emit */
    if (payload_len < 126) {
        out[o++] = (uint8_t)((mask ? 0x80 : 0) | payload_len);
    } else if (payload_len <= 0xFFFF) {
        out[o++] = (uint8_t)((mask ? 0x80 : 0) | 126);
        nl_put_u16(out + o, (uint16_t)payload_len);
        o += 2;
    } else {
        out[o++] = (uint8_t)((mask ? 0x80 : 0) | 127);
        nl_put_u64(out + o, (uint64_t)payload_len);
        o += 8;
    }

    if (mask) {
        uint8_t key[4];
        nl_crypto_random(key, 4);
        memcpy(out + o, key, 4);
        o += 4;
        if (payload_len > 0 && payload) {
            for (size_t i = 0; i < payload_len; i++)
                out[o + i] = (uint8_t)(payload[i] ^ key[i & 3]);
        }
        o += payload_len;
    } else if (payload_len > 0 && payload) {
        memcpy(out + o, payload, payload_len);
        o += payload_len;
    }
    return o;
}

size_t nl_ws_encode_binary(const uint8_t *payload, size_t payload_len,
                           bool mask, uint8_t *out, size_t out_cap) {
    return nl_ws_encode(NL_WS_OPCODE_BINARY, payload, payload_len, mask, out, out_cap);
}

/* ---- streaming decoder ---- */

void nl_ws_decoder_init(nl_ws_decoder_t *d) {
    memset(d, 0, sizeof(*d));
}

void nl_ws_decoder_free(nl_ws_decoder_t *d) {
    if (!d) return;
    free(d->acc);
    free(d->frag);
    memset(d, 0, sizeof(*d));
}

static bool acc_reserve(nl_ws_decoder_t *d, size_t extra) {
    if (d->acc_len + extra <= d->acc_cap) return true;
    size_t need = d->acc_cap ? d->acc_cap : 256;
    while (need < d->acc_len + extra) {
        if (need > SIZE_MAX / 2) return false;
        need *= 2;
    }
    /* Hard cap: one frame is at most 10-byte header + 4-byte mask +
     * NL_WS_MAX_MESSAGE payload (+ slack for a control frame behind it). */
    if (need > 16 + NL_WS_MAX_MESSAGE + 256) {
        need = 16 + NL_WS_MAX_MESSAGE + 256;
        if (d->acc_len + extra > need) return false;
    }
    uint8_t *p = (uint8_t *)realloc(d->acc, need);
    if (!p) return false;
    d->acc = p;
    d->acc_cap = need;
    return true;
}

int nl_ws_decoder_feed(nl_ws_decoder_t *d, const uint8_t *data, size_t len) {
    if (d->error) return -1;
    if (len == 0) return 0;
    if (!acc_reserve(d, len)) { d->error = true; return -1; }
    memcpy(d->acc + d->acc_len, data, len);
    d->acc_len += len;
    return 0;
}

static bool frag_reserve(nl_ws_decoder_t *d, size_t need) {
    if (need <= d->frag_cap) return true;
    size_t cap = d->frag_cap ? d->frag_cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) return false;
        cap *= 2;
    }
    if (cap > NL_WS_MAX_MESSAGE) cap = NL_WS_MAX_MESSAGE;
    if (need > cap) return false;
    uint8_t *p = (uint8_t *)realloc(d->frag, cap);
    if (!p) return false;
    d->frag = p;
    d->frag_cap = cap;
    return true;
}

/* Parse one frame from the front of d->acc. Returns:
 *   1 - frame consumed, deliver via out params (data frames go through
 *       frag reassembly; control frames deliver immediately)
 *   0 - need more bytes
 *  -1 - error (sets d->error)
 * For data messages still being reassembled, returns 0 with the frame
 * already consumed (caller just keeps feeding).
 */
static int decode_one(nl_ws_decoder_t *d, uint8_t *opcode, uint8_t *msg,
                      size_t msg_cap, size_t *msg_len) {
    if (d->error) return -1;
    if (d->acc_len < 2) return 0;

    uint8_t b0 = d->acc[0];
    uint8_t b1 = d->acc[1];
    bool fin = (b0 & 0x80) != 0;
    uint8_t rsv = (uint8_t)(b0 & 0x70);
    uint8_t op = (uint8_t)(b0 & 0x0F);
    bool masked = (b1 & 0x80) != 0;
    uint64_t plen = (uint64_t)(b1 & 0x7F);
    size_t hdr = 2;

    if (rsv != 0) { d->error = true; return -1; } /* no extensions negotiated */

    if (plen == 126) {
        if (d->acc_len < 4) return 0;
        plen = nl_get_u16(d->acc + 2);
        hdr = 4;
    } else if (plen == 127) {
        if (d->acc_len < 10) return 0;
        plen = nl_get_u64(d->acc + 2);
        hdr = 10;
        /* Reject non-minimal / oversized lengths early (plen > 2^63-1
         * is already illegal; we also refuse anything past our max). */
        if (plen > (uint64_t)NL_WS_MAX_MESSAGE) { d->error = true; return -1; }
    }

    bool is_control = (op & 0x8) != 0;
    if (is_control) {
        if (!fin || plen > 125) { d->error = true; return -1; }
    } else if (plen > (uint64_t)NL_WS_MAX_MESSAGE) {
        d->error = true;
        return -1;
    }

    size_t mask_len = masked ? 4 : 0;
    if (hdr > SIZE_MAX - mask_len) { d->error = true; return -1; }
    size_t frame_len = hdr + mask_len;
    if (plen > SIZE_MAX - frame_len) { d->error = true; return -1; }
    frame_len += (size_t)plen;

    if (d->acc_len < frame_len) return 0; /* incomplete */

    const uint8_t *payload = d->acc + hdr + mask_len;
    if (masked) {
        const uint8_t *key = d->acc + hdr;
        /* Unmask into a scratch region: copy to frag space for data, or
         * unmask in a local bounce for control (<=125). */
        if (is_control) {
            uint8_t tmp[125];
            for (uint64_t i = 0; i < plen; i++) tmp[i] = (uint8_t)(payload[i] ^ key[i & 3]);
            *opcode = op;
            *msg_len = (size_t)plen;
            if (msg_cap < (size_t)plen) { d->error = true; return -1; }
            memcpy(msg, tmp, (size_t)plen);
        } else {
            if (!frag_reserve(d, d->frag_len + (size_t)plen)) { d->error = true; return -1; }
            for (uint64_t i = 0; i < plen; i++)
                d->frag[d->frag_len + i] = (uint8_t)(payload[i] ^ key[i & 3]);
            d->frag_len += (size_t)plen;
        }
    } else {
        if (is_control) {
            *opcode = op;
            *msg_len = (size_t)plen;
            if (msg_cap < (size_t)plen) { d->error = true; return -1; }
            if (plen) memcpy(msg, payload, (size_t)plen);
        } else {
            if (!frag_reserve(d, d->frag_len + (size_t)plen)) { d->error = true; return -1; }
            if (plen) memcpy(d->frag + d->frag_len, payload, (size_t)plen);
            d->frag_len += (size_t)plen;
        }
    }

    /* Consume the frame. */
    if (frame_len < d->acc_len) {
        memmove(d->acc, d->acc + frame_len, d->acc_len - frame_len);
        d->acc_len -= frame_len;
    } else {
        d->acc_len = 0;
    }

    if (is_control) return 1;

    /* Data frame path: track fragmentation state. */
    if (!d->in_frag && op != NL_WS_OPCODE_CONT) {
        d->in_frag = !fin;
        d->frag_opcode = op;
        if (fin) {
            /* single-frame message already in frag[0..frag_len) */
            *opcode = d->frag_opcode;
            *msg_len = d->frag_len;
            if (msg_cap < d->frag_len) { d->error = true; return -1; }
            if (d->frag_len) memcpy(msg, d->frag, d->frag_len);
            d->frag_len = 0;
            d->in_frag = false;
            return 1;
        }
        return 0; /* wait for continuations */
    }

    if (op == NL_WS_OPCODE_CONT) {
        if (!d->in_frag) { d->error = true; return -1; }
        if (fin) {
            *opcode = d->frag_opcode;
            *msg_len = d->frag_len;
            if (msg_cap < d->frag_len) { d->error = true; return -1; }
            if (d->frag_len) memcpy(msg, d->frag, d->frag_len);
            d->frag_len = 0;
            d->in_frag = false;
            return 1;
        }
        return 0;
    }

    /* New data opcode mid-fragmentation is a protocol error. */
    d->error = true;
    return -1;
}

int nl_ws_decoder_next(nl_ws_decoder_t *d, uint8_t *opcode, uint8_t *msg,
                       size_t msg_cap, size_t *msg_len) {
    if (!d || !opcode || !msg || !msg_len) return -1;
    *msg_len = 0;
    *opcode = 0;
    for (;;) {
        size_t before = d->acc_len;
        int r = decode_one(d, opcode, msg, msg_cap, msg_len);
        if (r != 0) return r; /* 1 = deliverable message, -1 = error */
        if (d->error) return -1;
        /* decode_one returns 0 either when the head frame is incomplete
         * (acc unchanged) or after consuming a non-final data fragment
         * (acc shrunk). Loop only in the latter case so we pick up the
         * continuation frames that may already be buffered. */
        if (d->acc_len == before) return 0;
    }
}

/* ---- HTTP upgrade ---- */

static const char *find_header_end(const char *buf, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return buf + i;
    }
    return NULL;
}

bool nl_ws_http_header_complete(const char *buf, size_t len, size_t *hdr_end) {
    const char *end = find_header_end(buf, len);
    if (!end) return false;
    if (hdr_end) *hdr_end = (size_t)(end - buf) + 4;
    return true;
}

/* Case-insensitive header lookup. Returns value pointer/length for the
 * first occurrence of `name` (without the colon). */
static bool get_header(const char *headers, size_t len, const char *name,
                       const char **val, size_t *val_len) {
    size_t name_len = strlen(name);
    size_t i = 0;
    while (i < len) {
        /* find end of this line */
        size_t line_start = i;
        while (i + 1 < len && !(headers[i] == '\r' && headers[i + 1] == '\n')) i++;
        if (i + 1 >= len) break;
        size_t line_len = i - line_start;
        const char *line = headers + line_start;

        if (line_len > name_len) {
            bool match = true;
            for (size_t k = 0; k < name_len; k++) {
                char a = line[k];
                char b = name[k];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                if (a != b) { match = false; break; }
            }
            if (match && line[name_len] == ':') {
                size_t v = name_len + 1;
                while (v < line_len && (line[v] == ' ' || line[v] == '\t')) v++;
                *val = line + v;
                *val_len = line_len - v;
                /* trim trailing space */
                while (*val_len > 0 && ((*val)[*val_len - 1] == ' ' || (*val)[*val_len - 1] == '\t'))
                    (*val_len)--;
                return true;
            }
        }
        i += 2; /* skip CRLF */
        (void)line_start;
    }
    return false;
}

static bool header_token_contains(const char *val, size_t val_len, const char *token) {
    size_t tlen = strlen(token);
    for (size_t i = 0; i + tlen <= val_len; i++) {
        bool match = true;
        for (size_t k = 0; k < tlen; k++) {
            char a = val[i + k];
            char b = token[k];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) { match = false; break; }
        }
        if (!match) continue;
        /* token must be comma-delimited (or at edges) */
        bool left_ok = (i == 0) || val[i - 1] == ' ' || val[i - 1] == ',' || val[i - 1] == '\t';
        bool right_ok = (i + tlen == val_len) || val[i + tlen] == ' ' || val[i + tlen] == ',' ||
                        val[i + tlen] == '\t';
        if (left_ok && right_ok) return true;
        /* advance to next comma */
        while (i + tlen < val_len && val[i + tlen] != ',') i++;
    }
    return false;
}

bool nl_ws_check_client_request(const char *req, size_t len) {
    if (!req || len < 16) return false;
    size_t hdr_end = 0;
    if (!nl_ws_http_header_complete(req, len, &hdr_end)) return false;
    if (hdr_end > NL_WS_HTTP_MAX) return false;

    /* Request line: GET <path> HTTP/1.1 */
    if (len < 14 || strncmp(req, "GET ", 4) != 0) return false;
    const char *sp = memchr(req + 4, ' ', len - 4);
    if (!sp) return false;
    if ((size_t)(sp - req) + 8 > len || strncmp(sp + 1, "HTTP/1.1", 8) != 0) return false;

    const char *v; size_t vl;
    if (!get_header(req, hdr_end, "Upgrade", &v, &vl)) return false;
    if (!header_token_contains(v, vl, "websocket")) return false;
    if (!get_header(req, hdr_end, "Connection", &v, &vl)) return false;
    if (!header_token_contains(v, vl, "upgrade")) return false;
    if (!get_header(req, hdr_end, "Sec-WebSocket-Key", &v, &vl)) return false;
    if (vl < 8) return false; /* 16 bytes -> 24 base64 chars minimum-ish */
    if (!get_header(req, hdr_end, "Sec-WebSocket-Version", &v, &vl)) return false;
    if (vl != 2 || v[0] != '1' || v[1] != '3') return false;
    return true;
}

/* Extract Sec-WebSocket-Key value (trimmed). */
static bool get_ws_key(const char *req, size_t len, const char **key, size_t *key_len) {
    return get_header(req, len, "Sec-WebSocket-Key", key, key_len);
}

bool nl_ws_build_server_response(const char *req, size_t req_len,
                                 char *out, size_t out_cap, size_t *out_len) {
    if (!out || !out_len) return false;
    if (!nl_ws_check_client_request(req, req_len)) return false;
    size_t hdr_end = 0;
    nl_ws_http_header_complete(req, req_len, &hdr_end);

    const char *key; size_t key_len;
    if (!get_ws_key(req, hdr_end, &key, &key_len)) return false;
    if (key_len == 0 || key_len > 64) return false;

    /* accept = base64(sha1(key || GUID)) -- key is the raw header value. */
    uint8_t buf[64 + 36];
    if (key_len + sizeof(NL_WS_GUID) - 1 > sizeof(buf)) return false;
    memcpy(buf, key, key_len);
    memcpy(buf + key_len, NL_WS_GUID, sizeof(NL_WS_GUID) - 1);
    char accept[32];
    if (!nl_ws_base64_sha1(buf, key_len + sizeof(NL_WS_GUID) - 1, accept, sizeof(accept)))
        return false;

    int n = snprintf(out, out_cap,
                     "HTTP/1.1 101 Switching Protocols\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n"
                     "\r\n",
                     accept);
    if (n < 0 || (size_t)n >= out_cap) return false;
    *out_len = (size_t)n;
    return true;
}

bool nl_ws_build_client_request(const char *host, uint16_t port, const char *path,
                                char *out, size_t out_cap, size_t *out_len,
                                char accept_key_out[25]) {
    if (!host || !path || !out || !out_len || !accept_key_out) return false;
    uint8_t nonce[16];
    nl_crypto_random(nonce, sizeof(nonce));
    if (!nl_ws_base64_encode(nonce, sizeof(nonce), accept_key_out, 25)) return false;

    int n = snprintf(out, out_cap,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s:%u\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "\r\n",
                     path, host, (unsigned)port, accept_key_out);
    if (n < 0 || (size_t)n >= out_cap) return false;
    *out_len = (size_t)n;
    return true;
}

bool nl_ws_check_server_response(const char *resp, size_t len,
                                 const char accept_key[25]) {
    if (!resp || !accept_key || len < 16) return false;
    size_t hdr_end = 0;
    if (!nl_ws_http_header_complete(resp, len, &hdr_end)) return false;
    if (hdr_end > NL_WS_HTTP_MAX) return false;
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) return false;

    const char *v; size_t vl;
    if (!get_header(resp, hdr_end, "Upgrade", &v, &vl)) return false;
    if (!header_token_contains(v, vl, "websocket")) return false;
    if (!get_header(resp, hdr_end, "Connection", &v, &vl)) return false;
    if (!header_token_contains(v, vl, "upgrade")) return false;
    if (!get_header(resp, hdr_end, "Sec-WebSocket-Accept", &v, &vl)) return false;

    /* `accept_key` is the client's Sec-WebSocket-Key (the base64 nonce
     * we put on the wire); the server must echo base64(sha1(key||GUID)). */
    char expected[32];
    {
        uint8_t buf[64 + 36];
        size_t klen = strlen(accept_key);
        if (klen + sizeof(NL_WS_GUID) - 1 > sizeof(buf)) return false;
        memcpy(buf, accept_key, klen);
        memcpy(buf + klen, NL_WS_GUID, sizeof(NL_WS_GUID) - 1);
        if (!nl_ws_base64_sha1(buf, klen + sizeof(NL_WS_GUID) - 1, expected, sizeof(expected)))
            return false;
    }
    if (vl != strlen(expected)) return false;
    /* The accept value is derived from our own nonce and a public
     * constant; constant-time compare keeps the check uniform anyway. */
    return nl_crypto_const_time_eq((const uint8_t *)v, (const uint8_t *)expected, vl);
}
