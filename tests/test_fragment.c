#include "test_framework.h"
#include "../src/fragment.h"
#include <string.h>
#include <stdlib.h>

TEST(test_fragment_count_needed_basic) {
    ASSERT_EQ(nl_fragment_count_needed(0), 0);
    ASSERT_EQ(nl_fragment_count_needed(1), 1);
    ASSERT_EQ(nl_fragment_count_needed(NL_FRAGMENT_CHUNK_SIZE), 1);
    ASSERT_EQ(nl_fragment_count_needed(NL_FRAGMENT_CHUNK_SIZE + 1), 2);
    ASSERT_EQ(nl_fragment_count_needed(NL_FRAGMENT_CHUNK_SIZE * 3), 3);
}

TEST(test_fragment_count_needed_rejects_oversized) {
    ASSERT_EQ(nl_fragment_count_needed(NL_MAX_MESSAGE_SIZE + 1), 0);
}

TEST(test_fragment_get_chunk_splits_correctly) {
    size_t total = NL_FRAGMENT_CHUNK_SIZE + 100;
    uint8_t *data = (uint8_t *)malloc(total);
    for (size_t i = 0; i < total; i++) data[i] = (uint8_t)(i & 0xFF);

    const uint8_t *ptr; uint16_t len;
    nl_fragment_get_chunk(data, total, 0, &ptr, &len);
    ASSERT_EQ(len, NL_FRAGMENT_CHUNK_SIZE);
    ASSERT_TRUE(ptr == data);

    nl_fragment_get_chunk(data, total, 1, &ptr, &len);
    ASSERT_EQ(len, 100);
    ASSERT_TRUE(ptr == data + NL_FRAGMENT_CHUNK_SIZE);

    free(data);
}

TEST(test_reassembly_single_fragment_message) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);

    uint8_t chunk[] = "hello world";
    const uint8_t *out; uint32_t out_len;
    nl_reassemble_result_t r = nl_reassembly_feed(&t, 0, /*msg_id*/1, /*idx*/0, /*count*/1,
                                                   chunk, sizeof(chunk), &out, &out_len);
    ASSERT_EQ(r, NL_REASSEMBLE_COMPLETE);
    ASSERT_EQ(out_len, sizeof(chunk));
    ASSERT_MEM_EQ(out, chunk, sizeof(chunk));

    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_multi_fragment_in_order) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);

    size_t total = NL_FRAGMENT_CHUNK_SIZE * 2 + 50;
    uint8_t *data = (uint8_t *)malloc(total);
    for (size_t i = 0; i < total; i++) data[i] = (uint8_t)((i * 7) & 0xFF);

    uint16_t count = nl_fragment_count_needed(total);
    ASSERT_EQ(count, 3);

    const uint8_t *out = NULL; uint32_t out_len = 0;
    nl_reassemble_result_t r = NL_REASSEMBLE_PENDING;
    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *chunk_ptr; uint16_t chunk_len;
        nl_fragment_get_chunk(data, total, i, &chunk_ptr, &chunk_len);
        r = nl_reassembly_feed(&t, 0, 42, i, count, chunk_ptr, chunk_len, &out, &out_len);
        if (i < count - 1) ASSERT_EQ(r, NL_REASSEMBLE_PENDING);
    }
    ASSERT_EQ(r, NL_REASSEMBLE_COMPLETE);
    ASSERT_EQ(out_len, total);
    ASSERT_MEM_EQ(out, data, total);

    free(data);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_out_of_order_fragments) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);

    size_t total = NL_FRAGMENT_CHUNK_SIZE * 3;
    uint8_t *data = (uint8_t *)malloc(total);
    for (size_t i = 0; i < total; i++) data[i] = (uint8_t)(i & 0xFF);
    uint16_t count = nl_fragment_count_needed(total);

    const uint8_t *out; uint32_t out_len;
    const uint8_t *c0, *c1, *c2; uint16_t l0, l1, l2;
    nl_fragment_get_chunk(data, total, 0, &c0, &l0);
    nl_fragment_get_chunk(data, total, 1, &c1, &l1);
    nl_fragment_get_chunk(data, total, 2, &c2, &l2);

    /* Arrive in order 2, 0, 1 */
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 7, 2, count, c2, l2, &out, &out_len), NL_REASSEMBLE_PENDING);
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 7, 0, count, c0, l0, &out, &out_len), NL_REASSEMBLE_PENDING);
    nl_reassemble_result_t r = nl_reassembly_feed(&t, 0, 7, 1, count, c1, l1, &out, &out_len);
    ASSERT_EQ(r, NL_REASSEMBLE_COMPLETE);
    ASSERT_EQ(out_len, total);
    ASSERT_MEM_EQ(out, data, total);

    free(data);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_duplicate_fragment_is_idempotent) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    /* Non-final fragments must be exactly NL_FRAGMENT_CHUNK_SIZE (that's
     * what real senders produce); only the final one may be short. */
    uint8_t full[NL_FRAGMENT_CHUNK_SIZE]; memset(full, 0xAB, sizeof(full));
    uint8_t last[] = "abc";
    const uint8_t *out; uint32_t out_len;

    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 0, 2, full, sizeof(full), &out, &out_len), NL_REASSEMBLE_PENDING);
    /* Resend fragment 0 again (e.g. a duplicate delivery) -- must not
     * double-count toward completion or corrupt state. */
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 0, 2, full, sizeof(full), &out, &out_len), NL_REASSEMBLE_PENDING);
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 1, 2, last, 3, &out, &out_len), NL_REASSEMBLE_COMPLETE);
    ASSERT_EQ(out_len, NL_FRAGMENT_CHUNK_SIZE + 3);

    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_rejects_zero_fragment_count) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t chunk[] = "x";
    const uint8_t *out; uint32_t out_len;
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 0, 0, chunk, 1, &out, &out_len), NL_REASSEMBLE_INVALID);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_rejects_fragment_count_over_max) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t chunk[] = "x";
    const uint8_t *out; uint32_t out_len;
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 0, NL_MAX_FRAGMENTS + 1, chunk, 1, &out, &out_len),
              NL_REASSEMBLE_INVALID);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_rejects_index_out_of_range) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t chunk[] = "x";
    const uint8_t *out; uint32_t out_len;
    /* index must be < count */
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 5, 5, chunk, 1, &out, &out_len), NL_REASSEMBLE_INVALID);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_rejects_oversized_chunk) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t big[NL_FRAGMENT_CHUNK_SIZE + 1] = {0};
    const uint8_t *out; uint32_t out_len;
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 0, 2, big, sizeof(big), &out, &out_len), NL_REASSEMBLE_INVALID);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_rejects_short_non_final_fragment) {
    /* Only the LAST fragment may be shorter than the chunk size; a short
     * non-final fragment is a malformed/malicious claim. */
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t chunk[10] = {0};
    const uint8_t *out; uint32_t out_len;
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 0, 3, chunk, 10, &out, &out_len), NL_REASSEMBLE_INVALID);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_rejects_inconsistent_fragment_count) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t chunk[NL_FRAGMENT_CHUNK_SIZE] = {0};
    const uint8_t *out; uint32_t out_len;
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 0, 5, chunk, NL_FRAGMENT_CHUNK_SIZE, &out, &out_len),
              NL_REASSEMBLE_PENDING);
    /* Same message_id, but now claiming a different fragment_count. */
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 1, 1, 7, chunk, NL_FRAGMENT_CHUNK_SIZE, &out, &out_len),
              NL_REASSEMBLE_INVALID);
    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_bounded_concurrent_slots_evicts_oldest) {
    /* Fill all NL_REASSEMBLY_SLOTS with distinct incomplete messages, then
     * start one more -- the oldest incomplete one must be evicted rather
     * than growing memory unboundedly. */
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t full[NL_FRAGMENT_CHUNK_SIZE]; memset(full, 0, sizeof(full));
    const uint8_t *out; uint32_t out_len;

    for (int i = 0; i < NL_REASSEMBLY_SLOTS; i++) {
        nl_reassemble_result_t r = nl_reassembly_feed(&t, (uint64_t)i, (uint16_t)i, 0, 2, full, sizeof(full), &out, &out_len);
        ASSERT_EQ(r, NL_REASSEMBLE_PENDING);
    }
    /* One more, distinct message_id -- must evict message_id 0 (oldest). */
    nl_reassemble_result_t r = nl_reassembly_feed(&t, (uint64_t)NL_REASSEMBLY_SLOTS,
                                                   (uint16_t)NL_REASSEMBLY_SLOTS, 0, 2, full, sizeof(full), &out, &out_len);
    ASSERT_EQ(r, NL_REASSEMBLE_PENDING);

    /* message_id 0's remaining fragment should now start a FRESH reassembly
     * (its old progress was evicted), not complete it -- prove this by
     * feeding fragment 1 and checking it's still not complete (fragment 0
     * of the fresh attempt is still missing). */
    r = nl_reassembly_feed(&t, (uint64_t)100, 0, 1, 2, full, sizeof(full), &out, &out_len);
    ASSERT_EQ(r, NL_REASSEMBLE_PENDING);

    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_expiry_reclaims_stale_slot) {
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t full[NL_FRAGMENT_CHUNK_SIZE]; memset(full, 0, sizeof(full));
    const uint8_t *out; uint32_t out_len;

    nl_reassembly_feed(&t, 0, 1, 0, 2, full, sizeof(full), &out, &out_len);
    nl_reassembly_expire(&t, NL_REASSEMBLY_TIMEOUT_MS + 1);

    /* After expiry, message_id 1 restarting from fragment 0 should be a
     * fresh reassembly (PENDING again, not silently reusing stale data). */
    nl_reassemble_result_t r = nl_reassembly_feed(&t, NL_REASSEMBLY_TIMEOUT_MS + 2, 1, 0, 2, full, sizeof(full), &out, &out_len);
    ASSERT_EQ(r, NL_REASSEMBLE_PENDING);

    nl_reassembly_tracker_free(&t);
}

TEST(test_reassembly_message_id_reuse_after_completion) {
    /* After a message_id completes, it's legitimate for a later message to
     * reuse the same 16-bit id (wraparound) -- must behave as a fresh
     * reassembly, not accidentally merge with the old, already-delivered one. */
    nl_reassembly_tracker_t t;
    nl_reassembly_tracker_init(&t);
    uint8_t chunk[] = "first";
    const uint8_t *out; uint32_t out_len;
    ASSERT_EQ(nl_reassembly_feed(&t, 0, 9, 0, 1, chunk, 5, &out, &out_len), NL_REASSEMBLE_COMPLETE);

    uint8_t chunk2[] = "second-msg";
    ASSERT_EQ(nl_reassembly_feed(&t, 1, 9, 0, 1, chunk2, 10, &out, &out_len), NL_REASSEMBLE_COMPLETE);
    ASSERT_EQ(out_len, 10);
    ASSERT_MEM_EQ(out, chunk2, 10);

    nl_reassembly_tracker_free(&t);
}

int main(void) {
    printf("=== fragment tests ===\n");
    RUN_TEST(test_fragment_count_needed_basic);
    RUN_TEST(test_fragment_count_needed_rejects_oversized);
    RUN_TEST(test_fragment_get_chunk_splits_correctly);
    RUN_TEST(test_reassembly_single_fragment_message);
    RUN_TEST(test_reassembly_multi_fragment_in_order);
    RUN_TEST(test_reassembly_out_of_order_fragments);
    RUN_TEST(test_reassembly_duplicate_fragment_is_idempotent);
    RUN_TEST(test_reassembly_rejects_zero_fragment_count);
    RUN_TEST(test_reassembly_rejects_fragment_count_over_max);
    RUN_TEST(test_reassembly_rejects_index_out_of_range);
    RUN_TEST(test_reassembly_rejects_oversized_chunk);
    RUN_TEST(test_reassembly_rejects_short_non_final_fragment);
    RUN_TEST(test_reassembly_rejects_inconsistent_fragment_count);
    RUN_TEST(test_reassembly_bounded_concurrent_slots_evicts_oldest);
    RUN_TEST(test_reassembly_expiry_reclaims_stale_slot);
    RUN_TEST(test_reassembly_message_id_reuse_after_completion);
    TEST_SUMMARY();
}
