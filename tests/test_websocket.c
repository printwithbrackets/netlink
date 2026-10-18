/* Unit tests for RFC6455 WebSocket framing and the HTTP upgrade handshake
 * (src/websocket.c). Pure logic -- no sockets. */
#include "test_framework.h"
#include "../src/websocket.h"
#include "../src/crypto.h"
#include <string.h>
#include <stdlib.h>

/* ---- frame encoding ---- */

TEST(test_frame_encode_unmasked_binary_small) {
    const uint8_t payload[] = { 'h', 'i' };
    uint8_t out[16];
    size_t n = nl_ws_encode(NL_WS_OPCODE_BINARY, payload, 2, false, out, sizeof(out));
    ASSERT_EQ(n, 4); /* 2 header + 2 payload */
    ASSERT_EQ(out[0], 0x80 | NL_WS_OPCODE_BINARY); /* FIN + binary */
    ASSERT_EQ(out[1], 2); /* unmasked, len=2 */
    ASSERT_EQ(out[2], 'h');
    ASSERT_EQ(out[3], 'i');
}

TEST(test_frame_encode_masked_binary_small) {
    const uint8_t payload[] = { 'a', 'b', 'c' };
    uint8_t out[32];
    size_t n = nl_ws_encode(NL_WS_OPCODE_BINARY, payload, 3, true, out, sizeof(out));
    ASSERT_EQ(n, 2 + 4 + 3);
    ASSERT_EQ(out[0], 0x80 | NL_WS_OPCODE_BINARY);
    ASSERT_EQ(out[1], 0x80 | 3); /* MASK bit set */
    uint8_t mask[4];
    memcpy(mask, out + 2, 4);
    ASSERT_EQ((uint8_t)(out[6] ^ mask[0]), 'a');
    ASSERT_EQ((uint8_t)(out[7] ^ mask[1]), 'b');
    ASSERT_EQ((uint8_t)(out[8] ^ mask[2]), 'c');
}

TEST(test_frame_encode_16bit_length) {
    uint8_t payload[200];
    memset(payload, 0xAB, sizeof(payload));
    uint8_t out[256];
    size_t n = nl_ws_encode(NL_WS_OPCODE_BINARY, payload, 200, false, out, sizeof(out));
    ASSERT_EQ(n, 4 + 200); /* 2 header + 2 extended len */
    ASSERT_EQ(out[1], 126);
    ASSERT_EQ(out[2], 0);
    ASSERT_EQ(out[3], 200);
    ASSERT_MEM_EQ(out + 4, payload, 200);
}

TEST(test_frame_encode_rejects_tiny_output_buffer) {
    const uint8_t payload[] = { 1, 2, 3, 4, 5 };
    uint8_t out[4];
    size_t n = nl_ws_encode(NL_WS_OPCODE_BINARY, payload, 5, false, out, sizeof(out));
    ASSERT_EQ(n, 0);
}

TEST(test_frame_encode_rejects_reserved_opcodes) {
    const uint8_t payload[] = { 1, 2, 3 };
    uint8_t out[16];
    const uint8_t reserved[] = { 0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF };
    for (size_t i = 0; i < sizeof(reserved); i++) {
        ASSERT_EQ(nl_ws_encode(reserved[i], payload, sizeof(payload), false, out, sizeof(out)), 0);
        ASSERT_EQ(nl_ws_encode(reserved[i], payload, sizeof(payload), true, out, sizeof(out)), 0);
    }
    /* Defined opcodes still encode. */
    const uint8_t allowed[] = {
        NL_WS_OPCODE_CONT, NL_WS_OPCODE_TEXT, NL_WS_OPCODE_BINARY,
        NL_WS_OPCODE_CLOSE, NL_WS_OPCODE_PING, NL_WS_OPCODE_PONG,
    };
    for (size_t i = 0; i < sizeof(allowed); i++) {
        /* Control frames carry <=125 bytes; use 3 bytes so all pass. */
        ASSERT_TRUE(nl_ws_encode(allowed[i], payload, sizeof(payload), false, out, sizeof(out)) > 0);
    }
}

/* ---- frame decoding ---- */

TEST(test_frame_decode_roundtrip_unmasked) {
    const char *msg = "hello netlink";
    uint8_t frame[64];
    size_t flen = nl_ws_encode(NL_WS_OPCODE_BINARY, (const uint8_t *)msg, strlen(msg),
                               false, frame, sizeof(frame));
    ASSERT_TRUE(flen > 0);

    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    ASSERT_EQ(nl_ws_decoder_feed(&d, frame, flen), 0); /* incomplete: nothing delivered yet */
    uint8_t out[64];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 1);
    ASSERT_EQ(opcode, NL_WS_OPCODE_BINARY);
    ASSERT_EQ(out_len, strlen(msg));
    ASSERT_MEM_EQ(out, msg, out_len);
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 0);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_masked_client_frame) {
    /* Hand-craft a masked frame: payload "xyz", mask 01020304 */
    uint8_t frame[] = {
        0x82, 0x83,
        0x01, 0x02, 0x03, 0x04,
        (uint8_t)('x' ^ 0x01), (uint8_t)('y' ^ 0x02), (uint8_t)('z' ^ 0x03),
    };
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 1);
    ASSERT_EQ(opcode, NL_WS_OPCODE_BINARY);
    ASSERT_EQ(out_len, 3);
    ASSERT_MEM_EQ(out, "xyz", 3);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_byte_at_a_time) {
    const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42 };
    uint8_t frame[32];
    size_t flen = nl_ws_encode(NL_WS_OPCODE_BINARY, payload, sizeof(payload),
                               false, frame, sizeof(frame));

    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    uint8_t out[16];
    size_t out_len = 0;
    uint8_t opcode = 0;
    int got = 0;
    for (size_t i = 0; i < flen; i++) {
        nl_ws_decoder_feed(&d, frame + i, 1);
        int r = nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len);
        if (r == 1) {
            got = 1;
            ASSERT_EQ(out_len, sizeof(payload));
            ASSERT_MEM_EQ(out, payload, out_len);
            break;
        }
        ASSERT_EQ(r, 0);
    }
    ASSERT_TRUE(got);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_fragmented_message) {
    /* Two-fragment binary message: "hel" + "lo" (continuation, FIN on last). */
    uint8_t f1[] = { 0x02, 0x03, 'h', 'e', 'l' };           /* FIN=0 binary */
    uint8_t f2[] = { 0x80, 0x02, 'l', 'o' };                 /* FIN=1 continuation */

    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, f1, sizeof(f1));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 0);

    nl_ws_decoder_feed(&d, f2, sizeof(f2));
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 1);
    ASSERT_EQ(opcode, NL_WS_OPCODE_BINARY); /* first-frame opcode, not CONT */
    ASSERT_EQ(out_len, 5);
    ASSERT_MEM_EQ(out, "hello", 5);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_ping_control) {
    uint8_t frame[] = { 0x89, 0x02, 'p', 'g' }; /* FIN+ping, len 2 */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 1);
    ASSERT_EQ(opcode, NL_WS_OPCODE_PING);
    ASSERT_EQ(out_len, 2);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_close_control) {
    uint8_t frame[] = { 0x88, 0x02, 0x03, 0xE8 }; /* close, code 1000 */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 1);
    ASSERT_EQ(opcode, NL_WS_OPCODE_CLOSE);
    ASSERT_EQ(out_len, 2);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_rejects_oversized_message) {
    /* Claim a payload larger than NL_WS_MAX_MESSAGE via 16-bit length. */
    uint8_t frame[8];
    frame[0] = 0x82;
    frame[1] = 126;
    frame[2] = 0x7F; /* 0x7FFF = 32767 > max */
    frame[3] = 0xFF;
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[16];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_rejects_rsv_bits) {
    uint8_t frame[] = { 0xC2, 0x00 }; /* RSV1 set on binary */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[4];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

/* ---- HTTP upgrade handshake ---- */

TEST(test_handshake_rfc6455_test_vector) {
    /* The exact example from RFC 6455 section 1.3. */
    const char *req =
        "GET /chat HTTP/1.1\r\n"
        "Host: server.example.com\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";

    char resp[512];
    size_t resp_len = 0;
    ASSERT_TRUE(nl_ws_build_server_response(req, strlen(req), resp, sizeof(resp), &resp_len));
    ASSERT_TRUE(strstr(resp, "HTTP/1.1 101") != NULL);
    ASSERT_TRUE(strstr(resp, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != NULL);
}

TEST(test_handshake_client_request_and_server_accept_roundtrip) {
    char req[512];
    size_t req_len = 0;
    char accept[32];
    ASSERT_TRUE(nl_ws_build_client_request("127.0.0.1", 9000, "/", req, sizeof(req),
                                           &req_len, accept));
    ASSERT_TRUE(strstr(req, "GET / HTTP/1.1") != NULL);
    ASSERT_TRUE(strstr(req, "Upgrade: websocket") != NULL);
    ASSERT_TRUE(strstr(req, "Connection: Upgrade") != NULL);
    ASSERT_TRUE(strstr(req, "Sec-WebSocket-Key:") != NULL);
    ASSERT_TRUE(strstr(req, "Host: 127.0.0.1:9000") != NULL);
    ASSERT_TRUE(strstr(req, "Sec-WebSocket-Version: 13") != NULL);

    ASSERT_TRUE(nl_ws_check_client_request(req, req_len));

    char resp[512];
    size_t resp_len = 0;
    ASSERT_TRUE(nl_ws_build_server_response(req, req_len, resp, sizeof(resp), &resp_len));
    ASSERT_TRUE(nl_ws_check_server_response(resp, resp_len, accept));
}

TEST(test_handshake_rejects_non_websocket_request) {
    const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT_FALSE(nl_ws_check_client_request(req, strlen(req)));
    char resp[256];
    size_t resp_len = 0;
    ASSERT_FALSE(nl_ws_build_server_response(req, strlen(req), resp, sizeof(resp), &resp_len));
}

TEST(test_handshake_rejects_wrong_accept_from_server) {
    ASSERT_FALSE(nl_ws_check_server_response(
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: wrongwrongwrongwrongwrong=\r\n\r\n",
        90, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

TEST(test_handshake_rejects_not_101) {
    ASSERT_FALSE(nl_ws_check_server_response(
        "HTTP/1.1 400 Bad Request\r\n\r\n", 31,
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

TEST(test_frame_size_rejects_over_max) {
    /* The size helper is the gate for both encode paths: anything past
     * NL_WS_MAX_MESSAGE must be refused before a buffer is chosen. */
    ASSERT_EQ(nl_ws_frame_size(NL_WS_MAX_MESSAGE + 1, false), 0);
    ASSERT_EQ(nl_ws_frame_size(NL_WS_MAX_MESSAGE + 1, true), 0);
    ASSERT_EQ(nl_ws_frame_size(0xFFFFFFFFFFFFFFFFULL, false), 0);
    /* The boundary itself is still legal. 4096 >= 126, so it uses the
     * 16-bit extended length form (4-byte header), not the 2-byte one. */
    ASSERT_EQ(nl_ws_frame_size(NL_WS_MAX_MESSAGE, false), 4 + (size_t)NL_WS_MAX_MESSAGE);
    /* And encode agrees with frame_size at the boundary. */
    uint8_t *payload = (uint8_t *)malloc(NL_WS_MAX_MESSAGE);
    ASSERT_TRUE(payload != NULL);
    memset(payload, 0x5A, NL_WS_MAX_MESSAGE);
    uint8_t *out = (uint8_t *)malloc(NL_WS_MAX_MESSAGE + 16);
    ASSERT_TRUE(out != NULL);
    ASSERT_EQ(nl_ws_encode(NL_WS_OPCODE_BINARY, payload, NL_WS_MAX_MESSAGE, false,
                           out, NL_WS_MAX_MESSAGE + 16),
              4 + (size_t)NL_WS_MAX_MESSAGE);
    ASSERT_EQ(nl_ws_encode(NL_WS_OPCODE_BINARY, payload, NL_WS_MAX_MESSAGE + 1, false,
                           out, NL_WS_MAX_MESSAGE + 16),
              0);
    free(payload);
    free(out);
}

TEST(test_frame_decode_64bit_length_header) {
    /* A frame using the 64-bit length form (indicator 127) for a small
     * payload: header is 10 bytes, then the payload. The 127 decode path
     * must accept lengths within our max, not just reject big ones. */
    uint8_t frame[16];
    frame[0] = 0x82;                 /* FIN + binary */
    frame[1] = 0x7F;                 /* 64-bit length indicator */
    memset(frame + 2, 0, 7);
    frame[9] = 5;                    /* length = 5, big-endian u64 */
    memcpy(frame + 10, "hello", 5);

    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    ASSERT_EQ(nl_ws_decoder_feed(&d, frame, 15), 0);
    uint8_t out[16];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), 1);
    ASSERT_EQ(opcode, NL_WS_OPCODE_BINARY);
    ASSERT_EQ(out_len, 5);
    ASSERT_MEM_EQ(out, "hello", 5);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_rejects_unfinished_control_frame) {
    /* RFC 6455 5.5: control frames must not be fragmented. A ping with
     * FIN=0 is a protocol error and must poison the decoder. */
    uint8_t frame[] = { 0x09, 0x01, 'x' }; /* FIN=0 ping, len 1 */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_rejects_oversized_control_frame) {
    /* Control frames are capped at 125 payload bytes; a ping claiming 126
     * via the 16-bit length form must be rejected. */
    uint8_t frame[] = { 0x89, 126, 0x00, 126 }; /* FIN+ping, 16-bit len 126 */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_rejects_new_data_opcode_mid_fragmentation) {
    /* A fragmented message must continue with CONT frames: a new data
     * opcode (text) arriving while a binary message is still open is a
     * protocol error (RFC 6455 5.4). */
    uint8_t f1[] = { 0x02, 0x01, 'h' }; /* FIN=0 binary */
    uint8_t f2[] = { 0x81, 0x01, 'x' }; /* FIN=1 text (not CONT) */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, f1, sizeof(f1));
    nl_ws_decoder_feed(&d, f2, sizeof(f2));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_rejects_continuation_without_start) {
    /* A CONT frame with no open fragmented message is a protocol error. */
    uint8_t frame[] = { 0x80, 0x01, 'z' }; /* FIN=1 continuation */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

TEST(test_decoder_stays_poisoned_after_error) {
    /* After a protocol violation the decoder must be permanently poisoned:
     * both feed and next keep returning -1, so a caller that keeps using
     * it cannot be tricked into treating later bytes as valid frames. */
    uint8_t bad[] = { 0xC2, 0x00 }; /* RSV bits set */
    uint8_t good[] = { 0x82, 0x01, 'x' }; /* would be valid on its own */
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, bad, sizeof(bad));
    uint8_t out[8];
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    /* Poisoned: feeding more bytes (even valid ones) must not recover. */
    ASSERT_EQ(nl_ws_decoder_feed(&d, good, sizeof(good)), -1);
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

TEST(test_frame_decode_rejects_small_msg_cap) {
    /* A caller-supplied buffer smaller than the message must be an error,
     * never a silent truncation of attacker-controlled data. */
    uint8_t frame[] = { 0x82, 0x05, 'h', 'e', 'l', 'l', 'o' };
    nl_ws_decoder_t d;
    nl_ws_decoder_init(&d);
    nl_ws_decoder_feed(&d, frame, sizeof(frame));
    uint8_t out[4]; /* one byte too small */
    size_t out_len = 0;
    uint8_t opcode = 0;
    ASSERT_EQ(nl_ws_decoder_next(&d, &opcode, out, sizeof(out), &out_len), -1);
    nl_ws_decoder_free(&d);
}

TEST(test_http_header_complete_detects_crlfcrlf) {
    size_t end = 0;
    ASSERT_FALSE(nl_ws_http_header_complete("GET / HTTP/1.1\r\n", 17, &end));
    const char *full = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT_TRUE(nl_ws_http_header_complete(full, strlen(full), &end));
    ASSERT_EQ(end, strlen(full));
}

int main(void) {
    printf("websocket unit tests\n");
    RUN_TEST(test_frame_encode_unmasked_binary_small);
    RUN_TEST(test_frame_encode_masked_binary_small);
    RUN_TEST(test_frame_encode_16bit_length);
    RUN_TEST(test_frame_encode_rejects_tiny_output_buffer);
    RUN_TEST(test_frame_encode_rejects_reserved_opcodes);
    RUN_TEST(test_frame_decode_roundtrip_unmasked);
    RUN_TEST(test_frame_decode_masked_client_frame);
    RUN_TEST(test_frame_decode_byte_at_a_time);
    RUN_TEST(test_frame_decode_fragmented_message);
    RUN_TEST(test_frame_decode_ping_control);
    RUN_TEST(test_frame_decode_close_control);
    RUN_TEST(test_frame_decode_rejects_oversized_message);
    RUN_TEST(test_frame_decode_rejects_rsv_bits);
    RUN_TEST(test_handshake_rfc6455_test_vector);
    RUN_TEST(test_handshake_client_request_and_server_accept_roundtrip);
    RUN_TEST(test_handshake_rejects_non_websocket_request);
    RUN_TEST(test_handshake_rejects_wrong_accept_from_server);
    RUN_TEST(test_handshake_rejects_not_101);
    RUN_TEST(test_http_header_complete_detects_crlfcrlf);
    RUN_TEST(test_frame_size_rejects_over_max);
    RUN_TEST(test_frame_decode_64bit_length_header);
    RUN_TEST(test_frame_decode_rejects_unfinished_control_frame);
    RUN_TEST(test_frame_decode_rejects_oversized_control_frame);
    RUN_TEST(test_frame_decode_rejects_new_data_opcode_mid_fragmentation);
    RUN_TEST(test_frame_decode_rejects_continuation_without_start);
    RUN_TEST(test_decoder_stays_poisoned_after_error);
    RUN_TEST(test_frame_decode_rejects_small_msg_cap);
    TEST_SUMMARY();
}
