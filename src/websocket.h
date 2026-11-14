/* websocket.h - RFC6455 WebSocket framing and HTTP upgrade handshake.
 *
 * weft-net rides its existing datagram-shaped wire protocol inside binary
 * WebSocket messages: one WN packet (CONNECT_*, DATA, ACK, ...) per
 * unfragmented-or-reassembled BINARY frame. This module knows nothing
 * about weft-net packets or sockets -- it only frames bytes and performs
 * the opening HTTP handshake -- so it is unit-testable in isolation.
 *
 * Security notes:
 *   - The Sec-WebSocket-Accept value is SHA-1 over a public constant and
 *     the client's nonce; it is an interoperability check, not a secret.
 *     SHA-1 here is required by RFC 6455 and is not used for any
 *     integrity property weft-net relies on (packets are still AEAD-
 *     protected after the weft-net handshake).
 *   - Client-to-server frames MUST be masked (RFC 6455 §5.3); the
 *     endpoint layer passes mask=true for client endpoints. Server-to-
 *     client frames are unmasked.
 *   - Control frames (ping/pong/close) are capped at 125 bytes and must
 *     have FIN set; the decoder rejects violations so a hostile peer
 *     cannot force unbounded control-frame reassembly.
 */
#ifndef WEFT_NET_WEBSOCKET_H
#define WEFT_NET_WEBSOCKET_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define WN_WS_OPCODE_CONT   0x0
#define WN_WS_OPCODE_TEXT   0x1
#define WN_WS_OPCODE_BINARY 0x2
#define WN_WS_OPCODE_CLOSE  0x8
#define WN_WS_OPCODE_PING   0x9
#define WN_WS_OPCODE_PONG   0xA

/* Largest reassembled data message we will accept. weft-net packets are
 * bounded by WN_MAX_PACKET_SIZE (+ AEAD overhead); anything larger is a
 * protocol violation or an attempt to exhaust memory. */
#define WN_WS_MAX_MESSAGE 4096
/* Cap on buffered HTTP upgrade bytes before we give up on the handshake. */
#define WN_WS_HTTP_MAX 4096
/* RFC 6455 §1.3 magic GUID used to derive Sec-WebSocket-Accept. */
#define WN_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Wire size of a frame carrying `payload_len` bytes (header + optional
 * mask + payload). Returns 0 if the frame would not fit in a size_t or
 * the payload is too large for our limits. */
size_t wn_ws_frame_size(size_t payload_len, bool mask);

/* Encode one unfragmented frame into `out`. `mask` selects client
 * masking (random 4-byte key). Returns bytes written, or 0 on failure
 * (buffer too small / payload too large / invalid opcode). */
size_t wn_ws_encode(uint8_t opcode, const uint8_t *payload, size_t payload_len,
                    bool mask, uint8_t *out, size_t out_cap);

/* Convenience: binary data frame (what weft-net uses for WN packets). */
size_t wn_ws_encode_binary(const uint8_t *payload, size_t payload_len,
                           bool mask, uint8_t *out, size_t out_cap);

/* ---- streaming decoder ----
 *
 * Feed arbitrary byte chunks (TCP may split/merge frames). Call
 * wn_ws_decoder_next repeatedly after each feed; it returns:
 *   1  - one complete message is ready (*opcode / *msg / *msg_len)
 *   0  - need more bytes
 *  -1  - protocol violation (decoder is poisoned; free it)
 *
 * Data messages are reassembled across continuation frames. Control
 * frames are delivered immediately (must be FIN, len <= 125).
 */
typedef struct {
    uint8_t *acc;       /* unconsumed raw bytes */
    size_t   acc_len;
    size_t   acc_cap;
    uint8_t *frag;      /* partial data-message reassembly */
    size_t   frag_len;
    size_t   frag_cap;
    uint8_t  frag_opcode;
    bool     in_frag;
    bool     error;
} wn_ws_decoder_t;

void wn_ws_decoder_init(wn_ws_decoder_t *d);
void wn_ws_decoder_free(wn_ws_decoder_t *d);
int  wn_ws_decoder_feed(wn_ws_decoder_t *d, const uint8_t *data, size_t len);
int  wn_ws_decoder_next(wn_ws_decoder_t *d, uint8_t *opcode, uint8_t *msg,
                        size_t msg_cap, size_t *msg_len);

/* True when `buf[0..len)` ends exactly on a CRLFCRLF (complete HTTP
 * header block). *hdr_end (optional) receives the byte length including
 * the terminator. */
bool wn_ws_http_header_complete(const char *buf, size_t len, size_t *hdr_end);

/* Build a client opening handshake. Writes the request to `out`, stores
 * its length in *out_len, and writes the 24-char base64 nonce to
 * accept_key_out (must have room for 25 bytes including NUL) so the
 * caller can validate Sec-WebSocket-Accept later. */
bool wn_ws_build_client_request(const char *host, uint16_t port, const char *path,
                                char *out, size_t out_cap, size_t *out_len,
                                char accept_key_out[25]);

/* Validate a complete client request (method, upgrade headers, version
 * 13, present Sec-WebSocket-Key). */
bool wn_ws_check_client_request(const char *req, size_t len);

/* Build the 101 Switching Protocols response for a validated client
 * request. Returns false if the request is not a valid WebSocket
 * upgrade. */
bool wn_ws_build_server_response(const char *req, size_t req_len,
                                 char *out, size_t out_cap, size_t *out_len);

/* Validate a server's 101 response. `client_key` is the Sec-WebSocket-Key
 * value we sent (the 24-char base64 nonce from build_client_request); the
 * response's Sec-WebSocket-Accept must equal base64(SHA1(key||GUID)). */
bool wn_ws_check_server_response(const char *resp, size_t len,
                                 const char client_key[25]);

/* Compute base64(SHA1(data)) into out (NUL-terminated). out_cap must be
 * >= 3*ceil(len/4)+1. Exposed for tests; uses OpenSSL EVP (no hand-rolled
 * crypto). */
bool wn_ws_base64_sha1(const uint8_t *data, size_t len, char *out, size_t out_cap);

/* base64-encode raw bytes (NUL-terminated). */
bool wn_ws_base64_encode(const uint8_t *data, size_t len, char *out, size_t out_cap);

#endif /* WEFT_NET_WEBSOCKET_H */
