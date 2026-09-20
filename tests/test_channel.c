#include "test_framework.h"
#include "../src/channel.h"
#include <string.h>
#include <stdlib.h>

/* ---- a tiny in-memory "network" for feeding one channel's emitted
 * packets to another, with the ability to drop/reorder/duplicate ---- */

#define MAX_CAPTURED 512

typedef struct {
    uint8_t data[NL_MAX_PACKET_SIZE];
    uint16_t len;
} captured_packet_t;

typedef struct {
    captured_packet_t packets[MAX_CAPTURED];
    int count;
} capture_t;

static void capture_emit(void *ctx, const uint8_t *data, uint16_t len) {
    capture_t *c = (capture_t *)ctx;
    ASSERT_TRUE(c->count < MAX_CAPTURED);
    memcpy(c->packets[c->count].data, data, len);
    c->packets[c->count].len = len;
    c->count++;
}

#define NL_MAX_MESSAGE_SIZE_FOR_TEST (16 * 1024) /* keep test stack/struct size sane; we only send small test messages */

typedef struct {
    uint8_t data[8][NL_MAX_MESSAGE_SIZE_FOR_TEST];
    uint32_t len[8];
    uint8_t channel[8];
    nl_delivery_t delivery[8];
    int count;
} delivered_t;

static void capture_deliver(void *ctx, uint8_t channel_id, nl_delivery_t delivery, const uint8_t *data, uint32_t len) {
    delivered_t *d = (delivered_t *)ctx;
    ASSERT_TRUE(d->count < 8);
    ASSERT_TRUE(len <= sizeof(d->data[0]));
    memcpy(d->data[d->count], data, len);
    d->len[d->count] = len;
    d->channel[d->count] = channel_id;
    d->delivery[d->count] = delivery;
    d->count++;
}

TEST(test_unreliable_basic_roundtrip) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);

    capture_t cap = {0};
    const char *msg = "hello unreliable";
    nl_result_t r = nl_channel_send(&sender, 1000, 3, NL_UNRELIABLE, (const uint8_t *)msg, strlen(msg), capture_emit, &cap);
    ASSERT_EQ(r, NL_OK);
    ASSERT_EQ(cap.count, 1);

    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 1000, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 1);
    ASSERT_EQ(del.channel[0], 3);
    ASSERT_EQ(del.delivery[0], NL_UNRELIABLE);
    ASSERT_EQ(del.len[0], strlen(msg));
    ASSERT_MEM_EQ(del.data[0], msg, strlen(msg));

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_unreliable_sequenced_drops_stale) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    const char *m1 = "position update 1";
    const char *m2 = "position update 2";
    const char *m3 = "position update 3";
    nl_channel_send(&sender, 0, 0, NL_UNRELIABLE_SEQUENCED, (const uint8_t *)m1, strlen(m1), capture_emit, &cap);
    nl_channel_send(&sender, 0, 0, NL_UNRELIABLE_SEQUENCED, (const uint8_t *)m2, strlen(m2), capture_emit, &cap);
    nl_channel_send(&sender, 0, 0, NL_UNRELIABLE_SEQUENCED, (const uint8_t *)m3, strlen(m3), capture_emit, &cap);
    ASSERT_EQ(cap.count, 3);

    /* Simulate network reordering: 3 arrives before 2 (2 gets lost/late) */
    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del); /* m3 */
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del); /* m2, stale */

    ASSERT_EQ(del.count, 1); /* only m3 delivered; m2 dropped as stale */
    ASSERT_MEM_EQ(del.data[0], m3, strlen(m3));

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_reliable_unordered_delivers_all_ignores_order) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    const char *m1 = "a", *m2 = "b", *m3 = "c";
    nl_channel_send(&sender, 0, 2, NL_RELIABLE_UNORDERED, (const uint8_t *)m1, 1, capture_emit, &cap);
    nl_channel_send(&sender, 0, 2, NL_RELIABLE_UNORDERED, (const uint8_t *)m2, 1, capture_emit, &cap);
    nl_channel_send(&sender, 0, 2, NL_RELIABLE_UNORDERED, (const uint8_t *)m3, 1, capture_emit, &cap);

    delivered_t del = {0};
    /* deliver out of order: 2, 0, 1 */
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del);
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del);

    ASSERT_EQ(del.count, 3);
    /* delivered in arrival order (unordered mode), so c, a, b */
    ASSERT_EQ(del.data[0][0], 'c');
    ASSERT_EQ(del.data[1][0], 'a');
    ASSERT_EQ(del.data[2][0], 'b');

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_reliable_unordered_dedupes_retransmit) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};
    const char *m = "x";
    nl_channel_send(&sender, 0, 0, NL_RELIABLE_UNORDERED, (const uint8_t *)m, 1, capture_emit, &cap);

    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);
    /* simulate a spurious retransmit/duplicate delivery of the same packet */
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);

    ASSERT_EQ(del.count, 1); /* delivered exactly once to the application */

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_reliable_ordered_delivers_in_order_despite_network_reorder) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    const char *msgs[5] = {"one", "two", "three", "four", "five"};
    for (int i = 0; i < 5; i++) {
        nl_channel_send(&sender, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)msgs[i], strlen(msgs[i]), capture_emit, &cap);
    }
    ASSERT_EQ(cap.count, 5);

    /* Deliver scrambled: 0, 2, 1, 4, 3 */
    int order[5] = {0, 2, 1, 4, 3};
    delivered_t del = {0};
    for (int i = 0; i < 5; i++) {
        nl_channel_on_receive(&receiver, 0, cap.packets[order[i]].data, cap.packets[order[i]].len, capture_deliver, &del);
    }

    ASSERT_EQ(del.count, 5);
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(del.len[i], strlen(msgs[i]));
        ASSERT_MEM_EQ(del.data[i], msgs[i], strlen(msgs[i]));
    }

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_reliable_ordered_withholds_until_gap_fills) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    const char *msgs[3] = {"A", "B", "C"};
    for (int i = 0; i < 3; i++) {
        nl_channel_send(&sender, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)msgs[i], 1, capture_emit, &cap);
    }

    delivered_t del = {0};
    /* Packet 1 (B) is "lost" for now; deliver 0 (A) then 2 (C). */
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 1);
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 1); /* C withheld, waiting for B */

    /* B finally arrives (e.g. a retransmit) -- both B and C should release. */
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 3);
    ASSERT_EQ(del.data[0][0], 'A');
    ASSERT_EQ(del.data[1][0], 'B');
    ASSERT_EQ(del.data[2][0], 'C');

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_fragmented_reliable_ordered_message) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    size_t total = NL_FRAGMENT_CHUNK_SIZE * 2 + 300;
    uint8_t *big = (uint8_t *)malloc(total);
    for (size_t i = 0; i < total; i++) big[i] = (uint8_t)((i * 13 + 7) & 0xFF);

    nl_result_t r = nl_channel_send(&sender, 0, 5, NL_RELIABLE_ORDERED, big, total, capture_emit, &cap);
    ASSERT_EQ(r, NL_OK);
    ASSERT_EQ(cap.count, 3); /* 3 fragments */

    delivered_t del = {0};
    /* deliver fragments out of order */
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 0); /* incomplete + out of order, nothing deliverable */
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 0);
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);

    ASSERT_EQ(del.count, 1); /* the whole reassembled message delivered as one unit */
    ASSERT_EQ(del.len[0], total);

    /* Compare against a heap buffer since del.data is fixed-size */
    uint8_t *cmp = (uint8_t *)malloc(total);
    memcpy(cmp, del.data[0], total < sizeof(del.data[0]) ? total : sizeof(del.data[0]));
    ASSERT_TRUE(total <= sizeof(del.data[0]));
    ASSERT_MEM_EQ(cmp, big, total);

    free(cmp);
    free(big);
    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_multiple_channels_independent_sequence_spaces) {
    /* Two different channel_ids used on the SAME nl_channel_t instance
     * would collide in real usage (each channel_id gets its own
     * nl_channel_t in connection.c) -- this test instead proves that the
     * channel_id byte is carried through transparently so the layer above
     * can demux by it. */
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    nl_channel_send(&sender, 0, 7, NL_RELIABLE_ORDERED, (const uint8_t *)"chan7", 5, capture_emit, &cap);

    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 1);
    ASSERT_EQ(del.channel[0], 7);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_retransmission_on_tick_when_unacked) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    nl_channel_send(&sender, 0 /*now_ms*/, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"retry-me", 8, capture_emit, &cap);
    ASSERT_EQ(cap.count, 1);

    /* Not enough time has passed: no retransmit yet. */
    capture_t retrans = {0};
    bool give_up = false;
    nl_channel_tick(&sender, 0, /*now_ms*/ 50, /*rto_ms*/ 200, /*max_retries*/ 10, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 0);
    ASSERT_FALSE(give_up);

    /* Past the RTO with no ack received: must retransmit. */
    nl_channel_tick(&sender, 0, /*now_ms*/ 300, 200, 10, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 1);
    ASSERT_FALSE(give_up);

    /* The retransmitted packet must still be understood correctly by a receiver. */
    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 300, retrans.packets[0].data, retrans.packets[0].len, capture_deliver, &del);
    ASSERT_EQ(del.count, 1);
    ASSERT_MEM_EQ(del.data[0], "retry-me", 8);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_no_retransmit_after_ack_received) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    nl_channel_send(&sender, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"acked", 5, capture_emit, &cap);

    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del);

    /* Receiver's next send piggybacks an ack for what it received. */
    capture_t ack_cap = {0};
    nl_channel_send(&receiver, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"reply", 5, capture_emit, &ack_cap);
    nl_channel_on_receive(&sender, 0, ack_cap.packets[0].data, ack_cap.packets[0].len, capture_deliver, &del);

    /* Sender's packet is now acked -- ticking well past RTO must NOT retransmit it. */
    capture_t retrans = {0};
    bool give_up = false;
    nl_channel_tick(&sender, 0, 10000, 200, 10, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 0);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_give_up_after_max_retries) {
    nl_channel_t sender;
    nl_channel_init(&sender);
    capture_t cap = {0};
    nl_channel_send(&sender, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"x", 1, capture_emit, &cap);

    bool give_up = false;
    capture_t retrans;
    uint64_t t = 0;
    for (uint32_t i = 0; i < 3; i++) {
        t += 200;
        memset(&retrans, 0, sizeof(retrans));
        nl_channel_tick(&sender, 0, t, 200, /*max_retries*/ 3, capture_emit, &retrans, &give_up);
    }
    ASSERT_FALSE(give_up); /* exactly at max_retries, still under the "give up" threshold */

    t += 200;
    memset(&retrans, 0, sizeof(retrans));
    nl_channel_tick(&sender, 0, t, 200, 3, capture_emit, &retrans, &give_up);
    ASSERT_TRUE(give_up);

    nl_channel_free(&sender);
}

int main(void) {
    printf("=== channel tests ===\n");
    RUN_TEST(test_unreliable_basic_roundtrip);
    RUN_TEST(test_unreliable_sequenced_drops_stale);
    RUN_TEST(test_reliable_unordered_delivers_all_ignores_order);
    RUN_TEST(test_reliable_unordered_dedupes_retransmit);
    RUN_TEST(test_reliable_ordered_delivers_in_order_despite_network_reorder);
    RUN_TEST(test_reliable_ordered_withholds_until_gap_fills);
    RUN_TEST(test_fragmented_reliable_ordered_message);
    RUN_TEST(test_multiple_channels_independent_sequence_spaces);
    RUN_TEST(test_retransmission_on_tick_when_unacked);
    RUN_TEST(test_no_retransmit_after_ack_received);
    RUN_TEST(test_give_up_after_max_retries);
    TEST_SUMMARY();
}
