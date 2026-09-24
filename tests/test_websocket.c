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
    TEST_SUMMARY();
}
