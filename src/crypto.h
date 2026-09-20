/* crypto.h - all cryptographic operations, backed by OpenSSL's EVP API.
 *
 * Deliberately does NOT implement any primitive (AES, GCM, X25519, SHA256,
 * HMAC) itself -- hand-rolled crypto is exactly the kind of thing that
 * looks fine and is subtly broken. Every function here is a thin,
 * carefully-checked wrapper around libcrypto.
 *
 * Design:
 *   - Key exchange: X25519 ECDH with fresh ephemeral keys every connection
 *     (forward secrecy -- compromising a long-term key, if one existed,
 *     would not expose past sessions; here there IS no long-term key by
 *     default, every session is independently keyed).
 *   - Key derivation: HKDF-SHA256, so the raw ECDH output is never used
 *     directly as an encryption key.
 *   - Bulk encryption: AES-256-GCM, an authenticated cipher -- every
 *     encrypted packet is also tamper-evident. Packet header fields are
 *     passed as AAD so they're authenticated but not encrypted (the
 *     receiver needs to read them before it can decrypt).
 *   - Nonces: 96-bit GCM nonces built from a per-connection random salt
 *     XORed with a monotonically increasing 64-bit counter. A key is
 *     never reused with two different directions' counters (separate
 *     keys for client->server and server->client), and a connection is
 *     torn down long before a 64-bit counter could wrap.
 */
#ifndef NETLINK_CRYPTO_H
#define NETLINK_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define NL_KEY_SIZE 32
#define NL_HMAC_SIZE 32

typedef struct nl_keypair nl_keypair_t; /* opaque, holds EVP_PKEY* */

/* Fill `buf` with `len` cryptographically secure random bytes. Aborts the
 * process on failure (RAND_bytes failing means the system's CSPRNG is
 * broken, which is not a condition we can safely continue past). */
void nl_crypto_random(uint8_t *buf, size_t len);

/* Generate a fresh ephemeral X25519 keypair. Returns NULL on failure. */
nl_keypair_t *nl_keypair_generate(void);
void nl_keypair_free(nl_keypair_t *kp);
/* Copies the 32-byte raw public key out. */
bool nl_keypair_public(const nl_keypair_t *kp, uint8_t out[NL_KEY_SIZE]);

/* ECDH: derive the shared secret from our private key and the peer's raw
 * 32-byte public key. Returns false on failure (e.g. malformed peer key,
 * or -- extremely unlikely but checked -- a low-order/all-zero result). */
bool nl_crypto_x25519(const nl_keypair_t *my_keypair, const uint8_t peer_public[NL_KEY_SIZE],
                       uint8_t out_shared_secret[NL_KEY_SIZE]);

/* HKDF-SHA256(secret, salt, info) -> out_len bytes. */
bool nl_crypto_hkdf_sha256(const uint8_t *secret, size_t secret_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len);

/* HMAC-SHA256, truncated to out_len bytes (out_len <= 32). Used for the
 * stateless connect cookie. */
bool nl_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t out_len);

/* AES-256-GCM encrypt. `ciphertext_out` must have room for `plaintext_len`
 * bytes, `tag_out` must have room for 16 bytes. `nonce` must be exactly 12
 * bytes and MUST NOT be reused with the same key (see nl_nonce_* below). */
bool nl_crypto_aead_encrypt(const uint8_t key[NL_KEY_SIZE], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *ciphertext_out, uint8_t tag_out[16]);

/* AES-256-GCM decrypt + verify. Returns false (and writes nothing useful
 * to plaintext_out) if the tag doesn't match -- callers MUST check the
 * return value and drop the packet on failure rather than trusting
 * plaintext_out. */
bool nl_crypto_aead_decrypt(const uint8_t key[NL_KEY_SIZE], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t tag[16],
                             uint8_t *plaintext_out);

/* Build a 12-byte GCM nonce from a per-connection-direction random salt and
 * a monotonic counter: nonce = salt XOR big-endian(counter). Since the
 * counter increments by exactly 1 per packet and a connection never lives
 * long enough to send 2^64 packets, this never repeats for a given salt+key. */
void nl_nonce_build(const uint8_t salt[12], uint64_t counter, uint8_t out_nonce[12]);

/* Constant-time comparison, for comparing cookies/tags/MACs where a
 * timing side-channel could leak information to an attacker. */
bool nl_crypto_const_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

/* ---- Anti-replay ----
 *
 * The per-channel sequence/dedupe logic in seqbuf.h protects RELIABLE
 * lanes from replay (a replayed ciphertext decrypts to a duplicate inner
 * sequence number, which gets dropped). It does NOT cover UNRELIABLE
 * lanes, which intentionally skip dedupe for speed. Without a separate
 * check, an attacker who captures one valid encrypted UNRELIABLE packet
 * could replay it verbatim -- GCM would happily decrypt it again, since
 * replay is a protocol-level concern GCM does not address by itself.
 *
 * This is a standard 64-wide sliding-window replay guard (the same
 * approach IPsec/DTLS use), applied uniformly to every encrypted packet's
 * 64-bit nonce counter regardless of which channel/delivery mode it
 * belongs to. */

typedef struct {
    uint64_t highest;
    uint64_t bitmask; /* bit i set => (highest - i) already seen, i in [0,63] */
    bool     initialized;
} nl_replay_window_t;

void nl_replay_window_init(nl_replay_window_t *w);
/* Non-mutating check: would this counter currently be accepted? Use this
 * to cheaply reject obvious replays before spending CPU on AEAD
 * decryption. Does NOT modify the window -- callers must call
 * nl_replay_window_check() (below) only AFTER the packet has been
 * authenticated. If the window were updated before authentication, an
 * attacker could "burn" a counter value with a forged packet that fails
 * the AEAD tag check, causing the legitimate packet using that same
 * counter (e.g. a genuine retransmission) to later be wrongly rejected
 * as a replay -- a denial-of-service against the real peer. */
bool nl_replay_window_would_accept(const nl_replay_window_t *w, uint64_t counter);
/* Returns true and records `counter` if it's new (not a replay and not
 * expired out of the 64-wide window); false if it must be rejected. Only
 * call this on a packet that has ALREADY been authenticated. */
bool nl_replay_window_check(nl_replay_window_t *w, uint64_t counter);

#endif /* NETLINK_CRYPTO_H */
