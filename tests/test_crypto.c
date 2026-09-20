#include "test_framework.h"
#include "../src/crypto.h"
#include <string.h>

TEST(test_random_produces_different_output) {
    uint8_t a[32], b[32];
    nl_crypto_random(a, 32);
    nl_crypto_random(b, 32);
    ASSERT_TRUE(memcmp(a, b, 32) != 0);
}

TEST(test_keypair_generate_and_public) {
    nl_keypair_t *kp = nl_keypair_generate();
    ASSERT_TRUE(kp != NULL);
    uint8_t pub[32];
    ASSERT_TRUE(nl_keypair_public(kp, pub));
    uint8_t zero[32] = {0};
    ASSERT_FALSE(memcmp(pub, zero, 32) == 0); /* essentially never all-zero */
    nl_keypair_free(kp);
}

TEST(test_x25519_agreement) {
    nl_keypair_t *alice = nl_keypair_generate();
    nl_keypair_t *bob = nl_keypair_generate();
    uint8_t alice_pub[32], bob_pub[32];
    nl_keypair_public(alice, alice_pub);
    nl_keypair_public(bob, bob_pub);

    uint8_t secret_a[32], secret_b[32];
    ASSERT_TRUE(nl_crypto_x25519(alice, bob_pub, secret_a));
    ASSERT_TRUE(nl_crypto_x25519(bob, alice_pub, secret_b));

    ASSERT_MEM_EQ(secret_a, secret_b, 32);

    nl_keypair_free(alice);
    nl_keypair_free(bob);
}

TEST(test_x25519_different_peers_different_secrets) {
    nl_keypair_t *alice = nl_keypair_generate();
    nl_keypair_t *bob = nl_keypair_generate();
    nl_keypair_t *carol = nl_keypair_generate();
    uint8_t bob_pub[32], carol_pub[32];
    nl_keypair_public(bob, bob_pub);
    nl_keypair_public(carol, carol_pub);

    uint8_t secret_ab[32], secret_ac[32];
    nl_crypto_x25519(alice, bob_pub, secret_ab);
    nl_crypto_x25519(alice, carol_pub, secret_ac);
    ASSERT_TRUE(memcmp(secret_ab, secret_ac, 32) != 0);

    nl_keypair_free(alice);
    nl_keypair_free(bob);
    nl_keypair_free(carol);
}

TEST(test_x25519_rejects_all_zero_public_key) {
    /* The all-zero X25519 public key is a known low-order point that
     * forces an all-zero shared secret with ANY private key -- a
     * malicious peer could use this to try to force a predictable key. */
    nl_keypair_t *alice = nl_keypair_generate();
    uint8_t zero_pub[32] = {0};
    uint8_t secret[32];
    ASSERT_FALSE(nl_crypto_x25519(alice, zero_pub, secret));
    nl_keypair_free(alice);
}

TEST(test_hkdf_deterministic) {
    uint8_t secret[32]; nl_crypto_random(secret, 32);
    uint8_t salt[16] = "salt-material...";
    uint8_t info[] = "netlink v1 c2s";
    uint8_t out1[32], out2[32];
    ASSERT_TRUE(nl_crypto_hkdf_sha256(secret, 32, salt, 16, info, sizeof(info), out1, 32));
    ASSERT_TRUE(nl_crypto_hkdf_sha256(secret, 32, salt, 16, info, sizeof(info), out2, 32));
    ASSERT_MEM_EQ(out1, out2, 32);
}

TEST(test_hkdf_different_info_different_output) {
    uint8_t secret[32]; nl_crypto_random(secret, 32);
    uint8_t salt[16] = "salt-material...";
    uint8_t out_c2s[32], out_s2c[32];
    ASSERT_TRUE(nl_crypto_hkdf_sha256(secret, 32, salt, 16, (const uint8_t *)"c2s", 3, out_c2s, 32));
    ASSERT_TRUE(nl_crypto_hkdf_sha256(secret, 32, salt, 16, (const uint8_t *)"s2c", 3, out_s2c, 32));
    ASSERT_TRUE(memcmp(out_c2s, out_s2c, 32) != 0);
}

TEST(test_hmac_deterministic_and_key_sensitive) {
    uint8_t key1[16] = "key-one-material";
    uint8_t key2[16] = "key-two-material";
    uint8_t data[] = "some cookie material";
    uint8_t out1[16], out2[16], out3[16];
    ASSERT_TRUE(nl_crypto_hmac_sha256(key1, 16, data, sizeof(data), out1, 16));
    ASSERT_TRUE(nl_crypto_hmac_sha256(key1, 16, data, sizeof(data), out2, 16));
    ASSERT_TRUE(nl_crypto_hmac_sha256(key2, 16, data, sizeof(data), out3, 16));
    ASSERT_MEM_EQ(out1, out2, 16);
    ASSERT_TRUE(memcmp(out1, out3, 16) != 0);
}

TEST(test_aead_roundtrip) {
    uint8_t key[32]; nl_crypto_random(key, 32);
    uint8_t nonce[12]; nl_crypto_random(nonce, 12);
    uint8_t aad[] = {0x06, 1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t plaintext[] = "the quick brown fox jumps over the lazy dog";
    size_t pt_len = sizeof(plaintext);

    uint8_t ciphertext[64], tag[16];
    ASSERT_TRUE(nl_crypto_aead_encrypt(key, nonce, aad, sizeof(aad), plaintext, pt_len, ciphertext, tag));

    uint8_t decrypted[64];
    ASSERT_TRUE(nl_crypto_aead_decrypt(key, nonce, aad, sizeof(aad), ciphertext, pt_len, tag, decrypted));
    ASSERT_MEM_EQ(decrypted, plaintext, pt_len);
}

TEST(test_aead_wrong_key_fails) {
    uint8_t key[32]; nl_crypto_random(key, 32);
    uint8_t wrong_key[32]; nl_crypto_random(wrong_key, 32);
    uint8_t nonce[12]; nl_crypto_random(nonce, 12);
    uint8_t plaintext[] = "secret message";
    uint8_t ciphertext[32], tag[16], decrypted[32];

    nl_crypto_aead_encrypt(key, nonce, NULL, 0, plaintext, sizeof(plaintext), ciphertext, tag);
    ASSERT_FALSE(nl_crypto_aead_decrypt(wrong_key, nonce, NULL, 0, ciphertext, sizeof(plaintext), tag, decrypted));
}

TEST(test_aead_tampered_ciphertext_fails) {
    uint8_t key[32]; nl_crypto_random(key, 32);
    uint8_t nonce[12]; nl_crypto_random(nonce, 12);
    uint8_t plaintext[] = "secret message";
    uint8_t ciphertext[32], tag[16], decrypted[32];

    nl_crypto_aead_encrypt(key, nonce, NULL, 0, plaintext, sizeof(plaintext), ciphertext, tag);
    ciphertext[0] ^= 0xFF; /* flip a bit */
    ASSERT_FALSE(nl_crypto_aead_decrypt(key, nonce, NULL, 0, ciphertext, sizeof(plaintext), tag, decrypted));
}

TEST(test_aead_tampered_tag_fails) {
    uint8_t key[32]; nl_crypto_random(key, 32);
    uint8_t nonce[12]; nl_crypto_random(nonce, 12);
    uint8_t plaintext[] = "secret message";
    uint8_t ciphertext[32], tag[16], decrypted[32];

    nl_crypto_aead_encrypt(key, nonce, NULL, 0, plaintext, sizeof(plaintext), ciphertext, tag);
    tag[0] ^= 0xFF;
    ASSERT_FALSE(nl_crypto_aead_decrypt(key, nonce, NULL, 0, ciphertext, sizeof(plaintext), tag, decrypted));
}

TEST(test_aead_tampered_aad_fails) {
    /* AAD is authenticated even though it's not encrypted -- tampering
     * with header fields (e.g. flipping the channel or sequence) must be
     * detected even if the ciphertext itself is untouched. */
    uint8_t key[32]; nl_crypto_random(key, 32);
    uint8_t nonce[12]; nl_crypto_random(nonce, 12);
    uint8_t aad[] = {1, 2, 3, 4};
    uint8_t plaintext[] = "secret message";
    uint8_t ciphertext[32], tag[16], decrypted[32];

    nl_crypto_aead_encrypt(key, nonce, aad, sizeof(aad), plaintext, sizeof(plaintext), ciphertext, tag);
    aad[0] ^= 0xFF;
    ASSERT_FALSE(nl_crypto_aead_decrypt(key, nonce, aad, sizeof(aad), ciphertext, sizeof(plaintext), tag, decrypted));
}

TEST(test_aead_wrong_nonce_fails) {
    uint8_t key[32]; nl_crypto_random(key, 32);
    uint8_t nonce[12]; nl_crypto_random(nonce, 12);
    uint8_t wrong_nonce[12]; nl_crypto_random(wrong_nonce, 12);
    uint8_t plaintext[] = "secret message";
    uint8_t ciphertext[32], tag[16], decrypted[32];

    nl_crypto_aead_encrypt(key, nonce, NULL, 0, plaintext, sizeof(plaintext), ciphertext, tag);
    ASSERT_FALSE(nl_crypto_aead_decrypt(key, wrong_nonce, NULL, 0, ciphertext, sizeof(plaintext), tag, decrypted));
}

TEST(test_aead_decrypt_failure_zeroes_output) {
    uint8_t key[32]; nl_crypto_random(key, 32);
    uint8_t nonce[12]; nl_crypto_random(nonce, 12);
    uint8_t plaintext[] = "secret message";
    uint8_t ciphertext[32], tag[16];
    uint8_t decrypted[32];
    memset(decrypted, 0xAB, sizeof(decrypted)); /* poison */

    nl_crypto_aead_encrypt(key, nonce, NULL, 0, plaintext, sizeof(plaintext), ciphertext, tag);
    tag[0] ^= 1;
    ASSERT_FALSE(nl_crypto_aead_decrypt(key, nonce, NULL, 0, ciphertext, sizeof(plaintext), tag, decrypted));
    uint8_t zero[sizeof(plaintext)] = {0};
    ASSERT_MEM_EQ(decrypted, zero, sizeof(plaintext));
}

TEST(test_nonce_build_varies_with_counter) {
    uint8_t salt[12]; nl_crypto_random(salt, 12);
    uint8_t n0[12], n1[12], n_big[12];
    nl_nonce_build(salt, 0, n0);
    nl_nonce_build(salt, 1, n1);
    nl_nonce_build(salt, 0xFFFFFFFFFFFFFFFFULL, n_big);
    ASSERT_TRUE(memcmp(n0, n1, 12) != 0);
    ASSERT_TRUE(memcmp(n0, n_big, 12) != 0);
    ASSERT_TRUE(memcmp(n1, n_big, 12) != 0);
}

TEST(test_nonce_build_deterministic) {
    uint8_t salt[12]; nl_crypto_random(salt, 12);
    uint8_t a[12], b[12];
    nl_nonce_build(salt, 12345, a);
    nl_nonce_build(salt, 12345, b);
    ASSERT_MEM_EQ(a, b, 12);
}

TEST(test_const_time_eq) {
    uint8_t a[8] = {1,2,3,4,5,6,7,8};
    uint8_t b[8] = {1,2,3,4,5,6,7,8};
    uint8_t c[8] = {1,2,3,4,5,6,7,9};
    ASSERT_TRUE(nl_crypto_const_time_eq(a, b, 8));
    ASSERT_FALSE(nl_crypto_const_time_eq(a, c, 8));
}

TEST(test_replay_window_accepts_monotonic_sequence) {
    nl_replay_window_t w; nl_replay_window_init(&w);
    for (uint64_t i = 0; i < 1000; i++) {
        ASSERT_TRUE(nl_replay_window_check(&w, i));
    }
}

TEST(test_replay_window_rejects_exact_replay) {
    nl_replay_window_t w; nl_replay_window_init(&w);
    ASSERT_TRUE(nl_replay_window_check(&w, 5));
    ASSERT_FALSE(nl_replay_window_check(&w, 5)); /* replay of the exact same packet */
}

TEST(test_replay_window_accepts_reordered_within_window) {
    nl_replay_window_t w; nl_replay_window_init(&w);
    ASSERT_TRUE(nl_replay_window_check(&w, 10));
    ASSERT_TRUE(nl_replay_window_check(&w, 8));  /* arrived late but still new */
    ASSERT_TRUE(nl_replay_window_check(&w, 9));
    ASSERT_FALSE(nl_replay_window_check(&w, 8)); /* now a replay */
    ASSERT_FALSE(nl_replay_window_check(&w, 9));
    ASSERT_FALSE(nl_replay_window_check(&w, 10));
}

TEST(test_replay_window_rejects_too_old) {
    nl_replay_window_t w; nl_replay_window_init(&w);
    ASSERT_TRUE(nl_replay_window_check(&w, 1000));
    /* 1000 - 64 is exactly at the edge (age==64) -- outside the 64-wide window */
    ASSERT_FALSE(nl_replay_window_check(&w, 1000 - 64));
    /* age 63 is the oldest still-trackable position */
    ASSERT_TRUE(nl_replay_window_check(&w, 1000 - 63));
}

TEST(test_replay_window_large_forward_jump_resets_bitmask) {
    nl_replay_window_t w; nl_replay_window_init(&w);
    nl_replay_window_check(&w, 5);
    nl_replay_window_check(&w, 6);
    /* Jump far ahead (e.g. after a burst of loss) -- old bits must not
     * incorrectly mark unrelated future counters as already-seen. */
    ASSERT_TRUE(nl_replay_window_check(&w, 10000));
    ASSERT_TRUE(nl_replay_window_check(&w, 10001));
    ASSERT_FALSE(nl_replay_window_check(&w, 10000)); /* now a genuine replay */
}

TEST(test_replay_window_first_packet_always_accepted) {
    nl_replay_window_t w; nl_replay_window_init(&w);
    /* Even a "high" first counter value must be accepted -- there's no
     * prior state to compare against yet. */
    ASSERT_TRUE(nl_replay_window_check(&w, 999999));
    ASSERT_FALSE(nl_replay_window_check(&w, 999999));
}

TEST(test_replay_window_peek_does_not_mutate) {
    nl_replay_window_t w; nl_replay_window_init(&w);
    nl_replay_window_check(&w, 5);
    /* Peeking at a counter that would be accepted must not itself record
     * it -- simulates checking-before-decrypt on a packet that then fails
     * authentication (so it must remain available for a legitimate
     * future packet using the same counter). */
    ASSERT_TRUE(nl_replay_window_would_accept(&w, 6));
    ASSERT_TRUE(nl_replay_window_would_accept(&w, 6)); /* still true: peek didn't consume it */
    ASSERT_TRUE(nl_replay_window_check(&w, 6));         /* now actually commit it */
    ASSERT_FALSE(nl_replay_window_would_accept(&w, 6)); /* and now it's correctly rejected */
}

TEST(test_replay_window_forged_packet_cannot_burn_counter) {
    /* Regression test for the fix: a packet that fails authentication
     * must NOT be allowed to consume/burn a counter value via the replay
     * window, or an attacker could pre-emptively block the real peer's
     * legitimate packet with that counter (a DoS). This models the
     * correct call sequence a decrypt path must use: peek, then only
     * commit (nl_replay_window_check) after auth actually succeeds. */
    nl_replay_window_t w; nl_replay_window_init(&w);
    nl_replay_window_check(&w, 100);

    uint64_t forged_counter = 101;
    ASSERT_TRUE(nl_replay_window_would_accept(&w, forged_counter)); /* peek before decrypt */
    bool forged_auth_ok = false; /* simulate: AEAD tag check failed */
    if (forged_auth_ok) nl_replay_window_check(&w, forged_counter); /* not reached */

    /* The real peer's legitimate packet with the same counter must still
     * be accepted. */
    ASSERT_TRUE(nl_replay_window_would_accept(&w, forged_counter));
    ASSERT_TRUE(nl_replay_window_check(&w, forged_counter));
}

int main(void) {
    printf("=== crypto tests ===\n");
    RUN_TEST(test_random_produces_different_output);
    RUN_TEST(test_keypair_generate_and_public);
    RUN_TEST(test_x25519_agreement);
    RUN_TEST(test_x25519_different_peers_different_secrets);
    RUN_TEST(test_x25519_rejects_all_zero_public_key);
    RUN_TEST(test_hkdf_deterministic);
    RUN_TEST(test_hkdf_different_info_different_output);
    RUN_TEST(test_hmac_deterministic_and_key_sensitive);
    RUN_TEST(test_aead_roundtrip);
    RUN_TEST(test_aead_wrong_key_fails);
    RUN_TEST(test_aead_tampered_ciphertext_fails);
    RUN_TEST(test_aead_tampered_tag_fails);
    RUN_TEST(test_aead_tampered_aad_fails);
    RUN_TEST(test_aead_wrong_nonce_fails);
    RUN_TEST(test_aead_decrypt_failure_zeroes_output);
    RUN_TEST(test_nonce_build_varies_with_counter);
    RUN_TEST(test_nonce_build_deterministic);
    RUN_TEST(test_const_time_eq);
    RUN_TEST(test_replay_window_accepts_monotonic_sequence);
    RUN_TEST(test_replay_window_rejects_exact_replay);
    RUN_TEST(test_replay_window_accepts_reordered_within_window);
    RUN_TEST(test_replay_window_rejects_too_old);
    RUN_TEST(test_replay_window_large_forward_jump_resets_bitmask);
    RUN_TEST(test_replay_window_first_packet_always_accepted);
    RUN_TEST(test_replay_window_peek_does_not_mutate);
    RUN_TEST(test_replay_window_forged_packet_cannot_burn_counter);
    TEST_SUMMARY();
}
