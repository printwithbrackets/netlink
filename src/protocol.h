/*
 * protocol.h - internal wire format definitions.
 *
 * All multi-byte integer fields on the wire are big-endian ("network byte
 * order"). Use the wn_put_u16/wn_get_u16/etc helpers in byteorder.h to read
 * and write them -- never cast a buffer pointer to a struct pointer, to
 * stay safe on platforms with alignment requirements and to keep the
 * layout independent of struct padding.
 *
 * Packet layout (before encryption, "cleartext header" is always readable
 * so the receiver can route/decrypt; everything after it is the AEAD
 * ciphertext + 16-byte GCM tag for encrypted packet types):
 *
 *   byte 0       : packet_type (wn_packet_type_t)
 *   ...          : type-specific fields, see structs below
 *
 * For encrypted types (DATA, ACK, KEEPALIVE, DISCONNECT, CONNECT_ACCEPTED):
 *   byte 0       : packet_type
 *   bytes 1-8    : connection_id (u64)            \_ AAD (authenticated,
 *   bytes 9-16   : nonce_counter (u64)             / not encrypted)
 *   bytes 17..N-17: AES-256-GCM ciphertext
 *   last 16 bytes : GCM authentication tag
 */
#ifndef WEFT_NET_PROTOCOL_H
#define WEFT_NET_PROTOCOL_H

#include <stdint.h>

#define WN_MAGIC 0x574E4B31u /* "WNK1" */

typedef enum {
    WN_PKT_CONNECT_REQUEST   = 0x01,
    WN_PKT_CONNECT_CHALLENGE = 0x02,
    WN_PKT_CONNECT_RESPONSE  = 0x03,
    WN_PKT_CONNECT_ACCEPTED  = 0x04, /* encrypted */
    WN_PKT_CONNECT_DENIED    = 0x05,
    WN_PKT_DATA              = 0x06, /* encrypted */
    WN_PKT_DISCONNECT        = 0x07, /* encrypted */
    WN_PKT_KEEPALIVE         = 0x08, /* encrypted */
    WN_PKT_ACK               = 0x09, /* encrypted */
    WN_PKT_DISCOVERY_REQUEST = 0x0A,
    WN_PKT_DISCOVERY_RESPONSE= 0x0B,
} wn_packet_type_t;

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
 *   u32 capabilities          (WN_CAP_* bitmask the client supports;
 *                              server stores it and replies with its own
 *                              set in CONNECT_CHALLENGE; negotiated = AND)
 *
 * The connection_id is chosen by the client (a random 64-bit value, via
 * the same CSPRNG used for keys) rather than assigned by the server. This
 * is what lets wn_connect() hand the caller a usable wn_peer_id_t
 * synchronously, before the handshake completes, instead of forcing an
 * awkward "wait for an event to learn your own peer id" API. It has no
 * bearing on security: the id is just a demultiplexing key, never an
 * input to key derivation or authentication -- a colliding/malicious id
 * can at worst be rejected by the server (see connection.c's uniqueness
 * check) if it happens to match an existing connection, which a random
 * 64-bit value practically never does.
 */
#define WN_CONNECT_REQUEST_SIZE (1 + 4 + 2 + 1 + 8 + 32 + 16 + 4)

/* CONNECT_CHALLENGE:
 *   u8  type
 *   u8  server_pubkey[32]
 *   u8  server_nonce[16]
 *   u8  cookie[16]
 *   u32 capabilities          (server's advertised WN_CAP_* set; the
 *                              client ANDs this with its own to get the
 *                              negotiated set for the connection)
 */
#define WN_CONNECT_CHALLENGE_SIZE (1 + 32 + 16 + 16 + 4)

/* CONNECT_RESPONSE:
 *   u8  type
 *   u8  cookie[16]
 *   u8  client_pubkey[32]   (echoed back so the server can match the
 *                             response against the pending handshake entry
 *                             that created the cookie)
 *   u8  client_nonce[16]
 */
#define WN_CONNECT_RESPONSE_SIZE (1 + 16 + 32 + 16)

/* CONNECT_DENIED:
 *   u8  type
 *   u8  reason
 */
#define WN_CONNECT_DENIED_SIZE (1 + 1)

/* Largest of every cleartext handshake packet. Any buffer that holds one of
 * them for retransmission (pending_t.retry_packet, the retry_pending_handshakes
 * copy-out array, the per-role scratch buffers) must be sized with this rather
 * than with one particular packet's size: CONNECT_CHALLENGE is the biggest and
 * is stored server-side, while a REQUEST/RESPONSE-sized buffer silently
 * overflows on the CHALLENGE retransmit path. The _Static_asserts below make
 * that failure a compile error instead. */
#define WN_CONNECT_MAX_PACKET_SIZE (WN_CONNECT_REQUEST_SIZE > WN_CONNECT_CHALLENGE_SIZE \
                                     ? WN_CONNECT_REQUEST_SIZE : WN_CONNECT_CHALLENGE_SIZE)
_Static_assert(WN_CONNECT_MAX_PACKET_SIZE >= WN_CONNECT_REQUEST_SIZE, "");
_Static_assert(WN_CONNECT_MAX_PACKET_SIZE >= WN_CONNECT_CHALLENGE_SIZE, "");
_Static_assert(WN_CONNECT_MAX_PACKET_SIZE >= WN_CONNECT_RESPONSE_SIZE, "");
_Static_assert(WN_CONNECT_MAX_PACKET_SIZE >= WN_CONNECT_DENIED_SIZE, "");

typedef enum {
    WN_DENY_SERVER_FULL         = 1,
    WN_DENY_PROTOCOL_MISMATCH   = 2,
} wn_deny_reason_t;

/* ---- Encrypted packet cleartext header (the "AAD" portion) ---- */
#define WN_ENC_HEADER_SIZE (1 + 8 + 8) /* type + connection_id + nonce_counter */
#define WN_GCM_TAG_SIZE 16
#define WN_GCM_NONCE_SIZE 12

/* ---- DATA payload (this is what's inside the AEAD plaintext) ----
 *   u8  channel
 *   u8  delivery              (wn_delivery_t)
 *   u16 sequence
 *   u16 ack
 *   u64 ack_bits
 *   u8  ack_valid             (0/1: 0 means "this packet carries no ack" --
 *                               ack/ack_bits are then meaningless. Without
 *                               it a lane that has received nothing would
 *                               stamp the all-zero ack, which the peer
 *                               cannot distinguish from a real "I have
 *                               sequence 0" and would act on.)
 *   u16 rwnd                  (sender's receive window in bytes: how much
 *                               more unconsumed payload the sender is
 *                               willing to buffer -- flow control, distinct
 *                               from congestion control which bounds what
 *                               the *network* can carry)
 *   u8  is_fragment           (0 or 1)
 *   -- if is_fragment --
 *     u16 message_id
 *     u16 fragment_index
 *     u16 fragment_count
 *   -- payload bytes follow to end of plaintext --
 */
#define WN_DATA_HEADER_SIZE (1 + 1 + 2 + 2 + 8 + 1 + 2 + 1)
#define WN_FRAGMENT_HEADER_SIZE (2 + 2 + 2)

/* ---- ACK payload (AEAD plaintext of WN_PKT_ACK) ----
 * Sent when a reliable receive has no outgoing DATA to piggyback the
 * ack on (the "one-way traffic" case: acks would otherwise only ride
 * on DATA in the reverse direction, so a receiver that never sends app
 * data would never ack, stalling the sender until RTO). Carries the
 * same (ack, ack_bits, rwnd) triple a DATA header does, plus which
 * channel/lane it covers.
 *   u8  channel
 *   u8  delivery              (must be a reliable wn_delivery_t)
 *   u16 ack
 *   u64 ack_bits
 *   u8  ack_valid             (0/1: same meaning as in the DATA header)
 *   u16 rwnd                  (our advertised receive window)
 */
#define WN_ACK_PAYLOAD_SIZE (1 + 1 + 2 + 8 + 1 + 2)

/* Default receive window (bytes) advertised when nothing better is known.
 * Lives here so channel-level tests can stamp it without pulling in
 * connection.h; connection.c uses the same value as its initial capacity. */
#ifndef WN_RECV_WINDOW_DEFAULT
#define WN_RECV_WINDOW_DEFAULT 32768u
#endif

/* ---- DISCOVERY_REQUEST:
 *   u8  type
 *   u32 magic
 *   u32 nonce (echoed back, lets client match replies to probes)
 */
#define WN_DISCOVERY_REQUEST_SIZE (1 + 4 + 4)

/* ---- DISCOVERY_RESPONSE:
 *   u8  type
 *   u32 nonce
 *   u16 server_port
 *   u32 player_count
 *   u32 max_players
 *   u8  name_len
 *   u8  name[name_len]
 */
#define WN_DISCOVERY_RESPONSE_MIN_SIZE (1 + 4 + 2 + 4 + 4 + 1)

#endif /* WEFT_NET_PROTOCOL_H */
