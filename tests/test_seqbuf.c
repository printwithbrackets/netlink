#include "test_framework.h"
#include "../src/seqbuf.h"
#include <string.h>

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
    nl_send_ring_ack(&ring, seq, 0);
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
    nl_send_ring_ack(&ring, 4, ack_bits);
    ASSERT_TRUE(nl_send_ring_get(&ring, 4)->acked);
    ASSERT_TRUE(nl_send_ring_get(&ring, 3)->acked);  /* bit 0 */
    ASSERT_FALSE(nl_send_ring_get(&ring, 2)->acked); /* not set */
    ASSERT_TRUE(nl_send_ring_get(&ring, 1)->acked);  /* bit 2 */
    ASSERT_FALSE(nl_send_ring_get(&ring, 0)->acked); /* not set */
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
