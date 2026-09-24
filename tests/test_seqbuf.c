#include "test_framework.h"
#include "../src/seqbuf.h"
#include <string.h>

/* Small file-scope capture helper for tests that need to observe which
 * sequences nl_send_ring_fast_retransmit() fires for. */
static uint16_t g_fast_retransmit_fired[16];
static int g_fast_retransmit_count;

static void fast_retransmit_capture_reset(void) {
    g_fast_retransmit_count = 0;
}
static int fast_retransmit_capture_count(void) {
    return g_fast_retransmit_count;
}
static uint16_t fast_retransmit_capture_get(int i) {
    return g_fast_retransmit_fired[i];
}
static void fast_retransmit_capture(void *ctx, uint16_t sequence) {
    (void)ctx;
    if (g_fast_retransmit_count < 16) g_fast_retransmit_fired[g_fast_retransmit_count++] = sequence;
}

TEST(test_seq_greater_than_basic) {
    ASSERT_TRUE(nl_seq_greater_than(1, 0));
    ASSERT_TRUE(nl_seq_greater_than(100, 99));
    ASSERT_FALSE(nl_seq_greater_than(0, 1));
    ASSERT_FALSE(nl_seq_greater_than(5, 5));
}

TEST(test_seq_greater_than_wraparound) {
    /* 0 comes "after" 65535 */
    ASSERT_TRUE(nl_seq_greater_than(0, 65535));
    ASSERT_FALSE(nl_seq_greater_than(65535, 0));
    ASSERT_TRUE(nl_seq_greater_than(10, 65530));
}

TEST(test_send_ring_insert_and_get) {
    nl_send_ring_t ring;
    ASSERT_EQ(nl_send_ring_init(&ring), 0);

    uint8_t payload[] = {1, 2, 3, 4};
    uint16_t seq;
    ASSERT_TRUE(nl_send_ring_insert(&ring, payload, sizeof(payload), 1000, &seq));
    ASSERT_EQ(seq, 0);

    nl_send_slot_t *slot = nl_send_ring_get(&ring, 0);
    ASSERT_TRUE(slot != NULL);
    ASSERT_EQ(slot->len, 4);
    ASSERT_FALSE(slot->acked);
    ASSERT_MEM_EQ(slot->data, payload, 4);

    ASSERT_TRUE(nl_send_ring_get(&ring, 1) == NULL);

    nl_send_ring_free(&ring);
}

TEST(test_send_ring_sequence_increments) {
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seq;
    for (int i = 0; i < 10; i++) {
        nl_send_ring_insert(&ring, payload, 1, 0, &seq);
        ASSERT_EQ(seq, i);
    }
    nl_send_ring_free(&ring);
}

TEST(test_send_ring_ack_marks_slot) {
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seq;
    nl_send_ring_insert(&ring, payload, 1, 0, &seq);
    ASSERT_FALSE(nl_send_ring_get(&ring, seq)->acked);
    bool has_sample; uint32_t sample_ms;
    nl_send_ring_ack(&ring, seq, 0, 0, &has_sample, &sample_ms, NULL);
    ASSERT_TRUE(nl_send_ring_get(&ring, seq)->acked);
    nl_send_ring_free(&ring);
}

TEST(test_send_ring_ack_bitfield_marks_older) {
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seqs[5];
    for (int i = 0; i < 5; i++) nl_send_ring_insert(&ring, payload, 1, 0, &seqs[i]);
    /* seqs = 0,1,2,3,4. Ack seq=4 with bit0 set (=seq 3) and bit2 set (=seq 1). */
    uint32_t ack_bits = (1u << 0) | (1u << 2);
    bool has_sample; uint32_t sample_ms;
    nl_send_ring_ack(&ring, 4, ack_bits, 0, &has_sample, &sample_ms, NULL);
    ASSERT_TRUE(nl_send_ring_get(&ring, 4)->acked);
    ASSERT_TRUE(nl_send_ring_get(&ring, 3)->acked);  /* bit 0 */
    ASSERT_FALSE(nl_send_ring_get(&ring, 2)->acked); /* not set */
    ASSERT_TRUE(nl_send_ring_get(&ring, 1)->acked);  /* bit 2 */
    ASSERT_FALSE(nl_send_ring_get(&ring, 0)->acked); /* not set */
    nl_send_ring_free(&ring);
}

TEST(test_send_ring_ack_rtt_sample_clean) {
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seq;
    nl_send_ring_insert(&ring, payload, 1, /*send_time_ms*/ 1000, &seq);

    bool has_sample; uint32_t sample_ms;
    nl_send_ring_ack(&ring, seq, 0, /*now_ms*/ 1075, &has_sample, &sample_ms, NULL);
    ASSERT_TRUE(has_sample);
    ASSERT_EQ(sample_ms, 75);
    nl_send_ring_free(&ring);
}

TEST(test_send_ring_ack_no_rtt_sample_if_already_acked) {
    /* A duplicate/stale ack for something already acked must not produce
     * a second (meaningless) RTT sample. */
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seq;
    nl_send_ring_insert(&ring, payload, 1, 1000, &seq);

    bool has_sample; uint32_t sample_ms;
    nl_send_ring_ack(&ring, seq, 0, 1050, &has_sample, &sample_ms, NULL);
    ASSERT_TRUE(has_sample);

    nl_send_ring_ack(&ring, seq, 0, 1200, &has_sample, &sample_ms, NULL); /* duplicate ack */
    ASSERT_FALSE(has_sample);
    nl_send_ring_free(&ring);
}

TEST(test_send_ring_ack_no_rtt_sample_for_retransmitted) {
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seq;
    nl_send_ring_insert(&ring, payload, 1, 1000, &seq);
    nl_send_ring_get(&ring, seq)->retry_count = 1; /* simulate: this slot was retransmitted */

    bool has_sample; uint32_t sample_ms;
    nl_send_ring_ack(&ring, seq, 0, 1050, &has_sample, &sample_ms, NULL);
    ASSERT_FALSE(has_sample);
    nl_send_ring_free(&ring);
}

TEST(test_send_ring_ack_no_rtt_sample_from_bitfield_entries) {
    /* Only the newest (`ack`) sequence is ever a sample source -- entries
     * newly-acked purely via the bitfield never produce one, even if
     * they were never retransmitted, since their delivery timing relative
     * to `now_ms` doesn't isolate path RTT the way the newest ack does. */
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seq0, seq1;
    nl_send_ring_insert(&ring, payload, 1, 1000, &seq0);
    nl_send_ring_insert(&ring, payload, 1, 1010, &seq1);

    bool has_sample; uint32_t sample_ms;
    /* Ack seq1 directly (produces a sample) and seq0 via bit 0. */
    nl_send_ring_ack(&ring, seq1, 1u << 0, 1100, &has_sample, &sample_ms, NULL);
    ASSERT_TRUE(has_sample);       /* from seq1, the `ack` field itself */
    ASSERT_EQ(sample_ms, 90);      /* 1100 - 1010 */
    ASSERT_TRUE(nl_send_ring_get(&ring, seq0)->acked); /* seq0 acked too, via bitfield */
    nl_send_ring_free(&ring);
}

TEST(test_fast_retransmit_triggers_past_threshold) {
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seqs[5];
    for (int i = 0; i < 5; i++) nl_send_ring_insert(&ring, payload, 1, 0, &seqs[i]);

    /* ack=4, with seqs 1,2,3 acked via bitfield (bits 0,1,2 relative to 4),
     * seq 0 (age 4) still unacked -- 4 strictly-newer acked (1,2,3,4)
     * exceeds threshold 3. As in real usage (channel.c always calls
     * nl_send_ring_ack() before nl_send_ring_fast_retransmit() with the
     * same ack/ack_bits), apply the ack first so already-acked slots are
     * correctly excluded from the scan. */
    uint32_t ack_bits = (1u << 0) | (1u << 1) | (1u << 2);
    bool has_sample; uint32_t sample_ms;
    nl_send_ring_ack(&ring, 4, ack_bits, 0, &has_sample, &sample_ms, NULL);

    fast_retransmit_capture_reset();
    nl_send_ring_fast_retransmit(&ring, 4, ack_bits, 3, 100, fast_retransmit_capture, NULL);

    ASSERT_EQ(fast_retransmit_capture_count(), 1);
    ASSERT_EQ(fast_retransmit_capture_get(0), seqs[0]);
    /* Fast-retransmitting must bump retry_count and refresh send_time_ms,
     * exactly like a normal RTO retransmit. */
    ASSERT_EQ(nl_send_ring_get(&ring, seqs[0])->retry_count, 1u);
    ASSERT_EQ(nl_send_ring_get(&ring, seqs[0])->send_time_ms, 100u);

    nl_send_ring_free(&ring);
}

TEST(test_fast_retransmit_correct_without_prior_ack_call) {
    /* Regression test for the ordering-independence fix: this must give
     * the same correct result as test_fast_retransmit_triggers_past_threshold
     * even when nl_send_ring_ack was never called with these values first. */
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seqs[5];
    for (int i = 0; i < 5; i++) nl_send_ring_insert(&ring, payload, 1, 0, &seqs[i]);

    uint32_t ack_bits = (1u << 0) | (1u << 1) | (1u << 2); /* seqs 1,2,3 acked; seq 0's own bit not covered */

    fast_retransmit_capture_reset();
    nl_send_ring_fast_retransmit(&ring, 4, ack_bits, 3, 100, fast_retransmit_capture, NULL);

    ASSERT_EQ(fast_retransmit_capture_count(), 1);
    ASSERT_EQ(fast_retransmit_capture_get(0), seqs[0]);

    nl_send_ring_free(&ring);
}

TEST(test_fast_retransmit_skips_already_acked) {
    nl_send_ring_t ring;
    nl_send_ring_init(&ring);
    uint8_t payload[] = {0xAA};
    uint16_t seqs[5];
    for (int i = 0; i < 5; i++) nl_send_ring_insert(&ring, payload, 1, 0, &seqs[i]);
    bool has_sample; uint32_t sample_ms;
    nl_send_ring_ack(&ring, 4, (1u << 0) | (1u << 1) | (1u << 2) | (1u << 3), 0, &has_sample, &sample_ms, NULL);

    /* everything acked now -- nothing should fast-retransmit */
    fast_retransmit_capture_reset();
    nl_send_ring_fast_retransmit(&ring, 4, (1u << 0) | (1u << 1) | (1u << 2) | (1u << 3), 3, 100,
                                  fast_retransmit_capture, NULL);
    ASSERT_EQ(fast_retransmit_capture_count(), 0);
    nl_send_ring_free(&ring);
}

TEST(test_recv_dedupe_rejects_duplicates) {
    nl_recv_dedupe_t d;
    nl_recv_dedupe_init(&d);
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 5));
    ASSERT_FALSE(nl_recv_dedupe_insert(&d, 5)); /* dup */
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 6));
    ASSERT_FALSE(nl_recv_dedupe_insert(&d, 6));
    nl_recv_dedupe_free(&d);
}

TEST(test_recv_dedupe_out_of_order_accepted_once) {
    nl_recv_dedupe_t d;
    nl_recv_dedupe_init(&d);
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 10));
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 8));  /* arrives late, still new */
    ASSERT_FALSE(nl_recv_dedupe_insert(&d, 8)); /* now a dup */
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 9));
    nl_recv_dedupe_free(&d);
}

TEST(test_recv_dedupe_too_old_rejected) {
    nl_recv_dedupe_t d;
    nl_recv_dedupe_init(&d);
    nl_recv_dedupe_insert(&d, 1000);
    /* 1000 - 260 is outside the 256-wide window */
    ASSERT_FALSE(nl_recv_dedupe_insert(&d, 1000 - 260));
    nl_recv_dedupe_free(&d);
}

TEST(test_recv_dedupe_build_ack_bitfield) {
    nl_recv_dedupe_t d;
    nl_recv_dedupe_init(&d);
    nl_recv_dedupe_insert(&d, 0);
    nl_recv_dedupe_insert(&d, 1);
    /* skip 2 */
    nl_recv_dedupe_insert(&d, 3);
    nl_recv_dedupe_insert(&d, 4);

    uint16_t ack; uint32_t bits;
    nl_recv_dedupe_build_ack(&d, &ack, &bits);
    ASSERT_EQ(ack, 4);
    /* bit0 = seq 3 (received) -> 1
       bit1 = seq 2 (missing)  -> 0
       bit2 = seq 1 (received) -> 1
       bit3 = seq 0 (received) -> 1 */
    ASSERT_TRUE(bits & (1u << 0));
    ASSERT_FALSE(bits & (1u << 1));
    ASSERT_TRUE(bits & (1u << 2));
    ASSERT_TRUE(bits & (1u << 3));
    nl_recv_dedupe_free(&d);
}

TEST(test_recv_dedupe_wraparound) {
    nl_recv_dedupe_t d;
    nl_recv_dedupe_init(&d);
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 65534));
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 65535));
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 0)); /* wrapped */
    ASSERT_TRUE(nl_recv_dedupe_insert(&d, 1));
    ASSERT_FALSE(nl_recv_dedupe_insert(&d, 0)); /* dup, post-wrap */
    ASSERT_FALSE(nl_recv_dedupe_insert(&d, 65535)); /* dup, pre-wrap */
    nl_recv_dedupe_free(&d);
}

TEST(test_reorder_ring_in_order_passthrough) {
    nl_reorder_ring_t ring;
    nl_reorder_ring_init(&ring);
    uint8_t data[] = {1, 2, 3};
    uint8_t out[NL_MAX_PACKET_SIZE];
    uint16_t out_len;

    ASSERT_TRUE(nl_reorder_ring_insert(&ring, 0, data, 3));
    ASSERT_TRUE(nl_reorder_ring_pop_ready(&ring, out, &out_len));
    ASSERT_EQ(out_len, 3);
    ASSERT_MEM_EQ(out, data, 3);
    ASSERT_FALSE(nl_reorder_ring_pop_ready(&ring, out, &out_len)); /* nothing else ready */

    nl_reorder_ring_free(&ring);
}

TEST(test_reorder_ring_buffers_out_of_order) {
    nl_reorder_ring_t ring;
    nl_reorder_ring_init(&ring);
    uint8_t p0[] = {0}, p1[] = {1}, p2[] = {2};
    uint8_t out[NL_MAX_PACKET_SIZE];
    uint16_t out_len;

    /* Packet 0 arrives first and establishes the base sequence. */
    ASSERT_TRUE(nl_reorder_ring_insert(&ring, 0, p0, 1));
    ASSERT_TRUE(nl_reorder_ring_pop_ready(&ring, out, &out_len));
    ASSERT_EQ(out[0], 0);

    /* Packet 2 arrives before packet 1 -- buffered, not yet deliverable. */
    ASSERT_TRUE(nl_reorder_ring_insert(&ring, 2, p2, 1));
    ASSERT_FALSE(nl_reorder_ring_pop_ready(&ring, out, &out_len));

    /* Packet 1 arrives -- now both 1 and 2 should release, in order. */
    ASSERT_TRUE(nl_reorder_ring_insert(&ring, 1, p1, 1));
    ASSERT_TRUE(nl_reorder_ring_pop_ready(&ring, out, &out_len));
    ASSERT_EQ(out[0], 1);
    ASSERT_TRUE(nl_reorder_ring_pop_ready(&ring, out, &out_len));
    ASSERT_EQ(out[0], 2);
    ASSERT_FALSE(nl_reorder_ring_pop_ready(&ring, out, &out_len));

    nl_reorder_ring_free(&ring);
}

TEST(test_reorder_ring_rejects_stale_duplicate) {
    nl_reorder_ring_t ring;
    nl_reorder_ring_init(&ring);
    uint8_t p0[] = {0};
    uint8_t out[NL_MAX_PACKET_SIZE];
    uint16_t out_len;

    nl_reorder_ring_insert(&ring, 0, p0, 1);
    nl_reorder_ring_pop_ready(&ring, out, &out_len);
    /* Sequence 0 already delivered; a retransmitted duplicate must be rejected. */
    ASSERT_FALSE(nl_reorder_ring_insert(&ring, 0, p0, 1));

    nl_reorder_ring_free(&ring);
}

TEST(test_reorder_ring_baseline_is_always_zero_not_first_arrival) {
    /* Regression test: the ring must expect sequence 0 first regardless of
     * which sequence happens to physically arrive first. Previously, the
     * ring inferred its starting point from whatever packet arrived
     * first, so if the network reordered the very first two packets of a
     * stream (sequence 1 arriving before sequence 0), it would wrongly
     * treat sequence 1 as "the start" and deliver it immediately --
     * silently breaking the in-order guarantee. */
    nl_reorder_ring_t ring;
    nl_reorder_ring_init(&ring);
    uint8_t p0[] = {0xA0}, p1[] = {0xA1};
    uint8_t out[NL_MAX_PACKET_SIZE];
    uint16_t out_len;

    /* Sequence 1 arrives first (reordered by the network). */
    ASSERT_TRUE(nl_reorder_ring_insert(&ring, 1, p1, 1));
    ASSERT_FALSE(nl_reorder_ring_pop_ready(&ring, out, &out_len)); /* must NOT release yet */

    /* Sequence 0 finally arrives -- now both should release, in order. */
    ASSERT_TRUE(nl_reorder_ring_insert(&ring, 0, p0, 1));
    ASSERT_TRUE(nl_reorder_ring_pop_ready(&ring, out, &out_len));
    ASSERT_EQ(out[0], 0xA0);
    ASSERT_TRUE(nl_reorder_ring_pop_ready(&ring, out, &out_len));
    ASSERT_EQ(out[0], 0xA1);
    ASSERT_FALSE(nl_reorder_ring_pop_ready(&ring, out, &out_len));

    nl_reorder_ring_free(&ring);
}

int main(void) {
    printf("=== seqbuf tests ===\n");
    RUN_TEST(test_seq_greater_than_basic);
    RUN_TEST(test_seq_greater_than_wraparound);
    RUN_TEST(test_send_ring_insert_and_get);
    RUN_TEST(test_send_ring_sequence_increments);
    RUN_TEST(test_send_ring_ack_marks_slot);
    RUN_TEST(test_send_ring_ack_bitfield_marks_older);
    RUN_TEST(test_send_ring_ack_rtt_sample_clean);
    RUN_TEST(test_send_ring_ack_no_rtt_sample_if_already_acked);
    RUN_TEST(test_send_ring_ack_no_rtt_sample_for_retransmitted);
    RUN_TEST(test_send_ring_ack_no_rtt_sample_from_bitfield_entries);
    RUN_TEST(test_fast_retransmit_triggers_past_threshold);
    RUN_TEST(test_fast_retransmit_correct_without_prior_ack_call);
    RUN_TEST(test_fast_retransmit_skips_already_acked);
    RUN_TEST(test_recv_dedupe_rejects_duplicates);
    RUN_TEST(test_recv_dedupe_out_of_order_accepted_once);
    RUN_TEST(test_recv_dedupe_too_old_rejected);
    RUN_TEST(test_recv_dedupe_build_ack_bitfield);
    RUN_TEST(test_recv_dedupe_wraparound);
    RUN_TEST(test_reorder_ring_in_order_passthrough);
    RUN_TEST(test_reorder_ring_buffers_out_of_order);
    RUN_TEST(test_reorder_ring_rejects_stale_duplicate);
    RUN_TEST(test_reorder_ring_baseline_is_always_zero_not_first_arrival);
    TEST_SUMMARY();
}
