/*
 * protocol.h - internal wire format definitions.
 *
 * All multi-byte integer fields on the wire are big-endian ("network byte
 * order"). Use the nl_put_u16/nl_get_u16/etc helpers in byteorder.h to read
 * and write them -- never cast a buffer pointer to a struct pointer, to
 * stay safe on platforms with alignment requirements and to keep the
 * layout independent of struct padding.
 *
 * Packet layout (before encryption, "cleartext header" is always readable
 * so the receiver can route/decrypt; everything after it is the AEAD
 * ciphertext + 16-byte GCM tag for encrypted packet types):
 *
 *   byte 0       : packet_type (nl_packet_type_t)
 *   ...          : type-specific fields, see structs below
 *
 * For encrypted types (DATA, KEEPALIVE, DISCONNECT):
 *   byte 0       : packet_type
 *   bytes 1-8    : connection_id (u64)            \_ AAD (authenticated,
 *   bytes 9-16   : nonce_counter (u64)             /  not encrypted)
 *   bytes 17..N-17: AES-256-GCM ciphertext
 *   last 16 bytes : GCM authentication tag
 */
#ifndef NETLINK_PROTOCOL_H
#define NETLINK_PROTOCOL_H

#include <stdint.h>

#define NL_MAGIC 0x4E4C4B31u /* "NLK1" */

typedef enum {
    NL_PKT_CONNECT_REQUEST   = 0x01,
    NL_PKT_CONNECT_CHALLENGE = 0x02,
    NL_PKT_CONNECT_RESPONSE  = 0x03,
    NL_PKT_CONNECT_ACCEPTED  = 0x04, /* encrypted */
    NL_PKT_CONNECT_DENIED    = 0x05,
    NL_PKT_DATA              = 0x06, /* encrypted */
    NL_PKT_DISCONNECT        = 0x07, /* encrypted */
    NL_PKT_KEEPALIVE         = 0x08, /* encrypted */
    NL_PKT_DISCOVERY_REQUEST = 0x0A,
    NL_PKT_DISCOVERY_RESPONSE= 0x0B,
} nl_packet_type_t;

/* ---- Handshake packets (cleartext; authenticity comes from the cookie
 * HMAC and from the AEAD key-confirmation on the first encrypted packet,
 * not from these being signed individually) ---- */

/* CONNECT_REQUEST:
 *   u8  type
 *   u32 magic
 *   u16 protocol_version
 *   u8  requested_channels
 *   u64 connection_id        (chosen by the CLIENT, not the server -- see
 *                              note below)
 *   u8  client_pubkey[32]
 *   u8  client_nonce[16]
 *
 * The connection_id is chosen by the client (a random 64-bit value, via
 * the same CSPRNG used for keys) rather than assigned by the server. This
 * is what lets nl_connect() hand the caller a usable nl_peer_id_t
 * synchronously, before the handshake completes, instead of forcing an
 * awkward "wait for an event to learn your own peer id" API. It has no
 * bearing on security: the id is just a demultiplexing key, never an
 * input to key derivation or authentication -- a colliding/malicious id
 * can at worst be rejected by the server (see connection.c's uniqueness
 * check) if it happens to match an existing connection, which a random
 * 64-bit value practically never does.
 */
#define NL_CONNECT_REQUEST_SIZE (1 + 4 + 2 + 1 + 8 + 32 + 16)

/* CONNECT_CHALLENGE:
 *   u8  type
 *   u8  server_pubkey[32]
 *   u8  server_nonce[16]
 *   u8  cookie[16]
 */
#define NL_CONNECT_CHALLENGE_SIZE (1 + 32 + 16 + 16)

/* CONNECT_RESPONSE:
 *   u8  type
 *   u8  cookie[16]
 *   u8  client_pubkey[32]   (repeated so the server's cookie-verification
 *                             path can stay stateless if desired)
 *   u8  client_nonce[16]
 */
#define NL_CONNECT_RESPONSE_SIZE (1 + 16 + 32 + 16)

/* CONNECT_DENIED:
 *   u8  type
 *   u8  reason
 */
#define NL_CONNECT_DENIED_SIZE (1 + 1)

typedef enum {
    NL_DENY_SERVER_FULL         = 1,
    NL_DENY_PROTOCOL_MISMATCH   = 2,
    NL_DENY_BAD_COOKIE          = 3,
    NL_DENY_RATE_LIMITED        = 4,
} nl_deny_reason_t;

/* ---- Encrypted packet cleartext header (the "AAD" portion) ---- */
#define NL_ENC_HEADER_SIZE (1 + 8 + 8) /* type + connection_id + nonce_counter */
#define NL_GCM_TAG_SIZE 16
#define NL_GCM_NONCE_SIZE 12

/* ---- DATA payload (this is what's inside the AEAD plaintext) ----
 *   u8  channel
 *   u8  delivery              (nl_delivery_t)
 *   u16 sequence
 *   u16 ack
 *   u32 ack_bits
 *   u8  is_fragment           (0 or 1)
 *   -- if is_fragment --
 *     u16 message_id
 *     u16 fragment_index
 *     u16 fragment_count
 *   -- payload bytes follow to end of plaintext --
 */
#define NL_DATA_HEADER_SIZE (1 + 1 + 2 + 2 + 4 + 1)
#define NL_FRAGMENT_HEADER_SIZE (2 + 2 + 2)

/* ---- KEEPALIVE plaintext: empty, or 1 byte flag (0=ping,1=pong) + u32 echo ---- */
#define NL_KEEPALIVE_SIZE (1 + 4)

/* ---- DISCOVERY_REQUEST:
 *   u8  type
 *   u32 magic
 *   u32 nonce (echoed back, lets client match replies to probes)
 */
#define NL_DISCOVERY_REQUEST_SIZE (1 + 4 + 4)

/* ---- DISCOVERY_RESPONSE:
 *   u8  type
 *   u32 nonce
 *   u16 server_port
 *   u32 player_count
 *   u32 max_players
 *   u8  name_len
 *   u8  name[name_len]
 */
#define NL_DISCOVERY_RESPONSE_MIN_SIZE (1 + 4 + 2 + 4 + 4 + 1)

#endif /* NETLINK_PROTOCOL_H */
