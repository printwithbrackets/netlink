#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct nl_keypair {
    EVP_PKEY *pkey;
};

void nl_crypto_random(uint8_t *buf, size_t len) {
    if (len == 0) return;
    if (RAND_bytes(buf, (int)len) != 1) {
        /* The system CSPRNG failing is not a recoverable condition for a
         * security-sensitive library: continuing would mean generating
         * predictable keys/nonces. Fail loudly and immediately. */
        fprintf(stderr, "netlink: fatal: RAND_bytes failed, cannot obtain secure randomness\n");
        abort();
    }
}

nl_keypair_t *nl_keypair_generate(void) {
    nl_keypair_t *kp = (nl_keypair_t *)calloc(1, sizeof(nl_keypair_t));
    if (!kp) return NULL;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) { free(kp); return NULL; }

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        free(kp);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        free(kp);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    kp->pkey = pkey;
    return kp;
}

void nl_keypair_free(nl_keypair_t *kp) {
    if (!kp) return;
    if (kp->pkey) EVP_PKEY_free(kp->pkey);
    free(kp);
}

bool nl_keypair_public(const nl_keypair_t *kp, uint8_t out[NL_KEY_SIZE]) {
    size_t len = NL_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(kp->pkey, out, &len) != 1) return false;
    return len == NL_KEY_SIZE;
}

bool nl_crypto_x25519(const nl_keypair_t *my_keypair, const uint8_t peer_public[NL_KEY_SIZE],
                       uint8_t out_shared_secret[NL_KEY_SIZE]) {
    bool ok = false;
    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, NL_KEY_SIZE);
    if (!peer_pkey) return false;

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(my_keypair->pkey, NULL);
    if (!dctx) goto out_free_peer;

    if (EVP_PKEY_derive_init(dctx) != 1) goto out_free_ctx;
    if (EVP_PKEY_derive_set_peer(dctx, peer_pkey) != 1) goto out_free_ctx;

    size_t secret_len = NL_KEY_SIZE;
    if (EVP_PKEY_derive(dctx, out_shared_secret, &secret_len) != 1) goto out_free_ctx;
    if (secret_len != NL_KEY_SIZE) goto out_free_ctx;

    /* Reject an all-zero shared secret. X25519 has known low-order points
     * that a malicious peer could send to force a predictable/degenerate
     * shared secret; while X25519 as specified doesn't require this check
     * for security against a passive attacker, checking costs nothing and
     * defends against a peer trying to downgrade the exchange. */
    uint8_t zero[NL_KEY_SIZE] = {0};
    if (nl_crypto_const_time_eq(out_shared_secret, zero, NL_KEY_SIZE)) goto out_free_ctx;

    ok = true;

out_free_ctx:
    EVP_PKEY_CTX_free(dctx);
out_free_peer:
    EVP_PKEY_free(peer_pkey);
    return ok;
}

bool nl_crypto_hkdf_sha256(const uint8_t *secret, size_t secret_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len) {
    bool ok = false;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) return false;

    if (EVP_PKEY_derive_init(kctx) != 1) goto out_free;
    if (EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) != 1) goto out_free;
    if (EVP_PKEY_CTX_set1_hkdf_salt(kctx, salt, (int)salt_len) != 1) goto out_free;
    if (EVP_PKEY_CTX_set1_hkdf_key(kctx, secret, (int)secret_len) != 1) goto out_free;
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(kctx, info, (int)info_len) != 1) goto out_free;
    }

    size_t len = out_len;
    if (EVP_PKEY_derive(kctx, out, &len) != 1) goto out_free;
    if (len != out_len) goto out_free;

    ok = true;
out_free:
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

bool nl_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t out_len) {
    if (out_len > 32) return false;
    uint8_t full[32];
    unsigned int full_len = 0;
    if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, full, &full_len) == NULL) {
        return false;
    }
    if (full_len != 32) return false;
    memcpy(out, full, out_len);
    return true;
}

bool nl_crypto_aead_encrypt(const uint8_t key[NL_KEY_SIZE], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *ciphertext_out, uint8_t tag_out[16]) {
    bool ok = false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;

    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    }

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, (int)plaintext_len) != 1) goto out;
        if ((size_t)len != plaintext_len) goto out; /* GCM is a stream cipher: must be 1:1 */
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext_out + len, &final_len) != 1) goto out;
    /* GCM never produces extra bytes on finalize, but don't assume it --
     * verify rather than silently truncating/overflowing the caller's
     * buffer sizing assumptions. */
    if (final_len != 0) goto out;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_out) != 1) goto out;

    ok = true;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool nl_crypto_aead_decrypt(const uint8_t key[NL_KEY_SIZE], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t tag[16],
                             uint8_t *plaintext_out) {
    bool ok = false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;

    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    }

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, (int)ciphertext_len) != 1) goto out;
        if ((size_t)len != ciphertext_len) goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto out;

    int final_len = 0;
    /* This is the authentication check: EVP_DecryptFinal_ex returns <= 0
     * if the tag doesn't match. On failure we must NOT trust
     * plaintext_out -- the caller contract says so, and we additionally
     * scrub it here so a caller that forgets to check the return value
     * gets zeros instead of attacker-controlled unauthenticated data. */
    int ret = EVP_DecryptFinal_ex(ctx, plaintext_out + len, &final_len);
    if (ret <= 0 || final_len != 0) {
        if (ciphertext_len > 0) memset(plaintext_out, 0, ciphertext_len);
        goto out;
    }

    ok = true;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void nl_nonce_build(const uint8_t salt[12], uint64_t counter, uint8_t out_nonce[12]) {
    uint8_t ctr_be[12] = {0};
    for (int i = 0; i < 8; i++) {
        ctr_be[4 + i] = (uint8_t)(counter >> (56 - 8 * i));
    }
    for (int i = 0; i < 12; i++) {
        out_nonce[i] = salt[i] ^ ctr_be[i];
    }
}

bool nl_crypto_const_time_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

void nl_replay_window_init(nl_replay_window_t *w) {
    w->highest = 0;
    w->bitmask = 0;
    w->initialized = false;
}

bool nl_replay_window_would_accept(const nl_replay_window_t *w, uint64_t counter) {
    if (!w->initialized) return true;
    if (counter > w->highest) return true; /* always new */
    uint64_t age = w->highest - counter;
    if (age >= 64) return false; /* too old to track */
    uint64_t bit = 1ULL << age;
    return (w->bitmask & bit) == 0; /* true iff not already seen */
}

bool nl_replay_window_check(nl_replay_window_t *w, uint64_t counter) {
    if (!w->initialized) {
        w->initialized = true;
        w->highest = counter;
        w->bitmask = 1; /* bit 0 = highest itself, now seen */
        return true;
    }

    if (counter > w->highest) {
        uint64_t shift = counter - w->highest;
        if (shift >= 64) {
            w->bitmask = 0;
        } else {
            w->bitmask <<= shift;
        }
        w->bitmask |= 1;
        w->highest = counter;
        return true;
    }

    uint64_t age = w->highest - counter;
    if (age >= 64) return false; /* too old to track: treat as replay */
    uint64_t bit = 1ULL << age;
    if (w->bitmask & bit) return false; /* already seen */
    w->bitmask |= bit;
    return true;
}
