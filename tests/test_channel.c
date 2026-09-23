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
    nl_channel_on_receive(&receiver, 1000, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
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
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del, NULL, NULL, NULL, NULL); /* m3 */
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del, NULL, NULL, NULL, NULL); /* m2, stale */

    ASSERT_EQ(del.count, 1); /* only m3 delivered; m2 dropped as stale */
    ASSERT_MEM_EQ(del.data[0], m3, strlen(m3));

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

/* Regression: fragmented UNRELIABLE_SEQUENCED messages must not be gated
 * per-fragment on seq_highest_seen -- that would drop the earlier fragment
 * of a reordered pair and strand reassembly incomplete forever. Each
 * fragment must reach reassembly; the stale-drop gate applies only once
 * the whole message is ready to deliver. */
TEST(test_sequenced_fragmented_reassembles_out_of_order_fragments) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    /* >1 fragment so the fragmented sequenced path is taken. */
    size_t total = NL_FRAGMENT_CHUNK_SIZE + 300;
    uint8_t *big = (uint8_t *)malloc(total);
    for (size_t i = 0; i < total; i++) big[i] = (uint8_t)((i * 17 + 3) & 0xFF);

    nl_result_t r = nl_channel_send(&sender, 0, 0, NL_UNRELIABLE_SEQUENCED, big, total, capture_emit, &cap);
    ASSERT_EQ(r, NL_OK);
    ASSERT_TRUE(cap.count >= 2); /* at least 2 fragments */

    /* Deliver fragments in reverse arrival order. Before the fix, fragment
     * 0 would be dropped as "stale" relative to a higher sequence already
     * seen from fragment 1, and the message would never reassemble. */
    delivered_t del = {0};
    for (int i = cap.count - 1; i >= 0; i--) {
        nl_channel_on_receive(&receiver, 0, cap.packets[i].data, cap.packets[i].len,
                               capture_deliver, &del, NULL, NULL, NULL, NULL);
    }

    ASSERT_EQ(del.count, 1); /* whole message delivered exactly once */
    ASSERT_EQ(del.len[0], (uint32_t)total);
    uint8_t *cmp = (uint8_t *)malloc(total);
    memcpy(cmp, del.data[0], total < sizeof(del.data[0]) ? total : sizeof(del.data[0]));
    ASSERT_TRUE(total <= sizeof(del.data[0]));
    ASSERT_MEM_EQ(cmp, big, total);

    free(cmp);
    free(big);
    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

/* Regression: nl_channel_tick must reclaim stale reassembly slots via
 * nl_reassembly_expire on every lane, not only under eviction pressure.
 * Without this, incomplete messages pinned their slots until the table
 * filled (fragment.h documents tick as the expected caller). */
TEST(test_channel_tick_expires_stale_reassembly) {
    nl_channel_t chan;
    nl_channel_init(&chan);
    capture_t cap = {0};

    /* NL_UNRELIABLE so the sequence-dedupe path doesn't interfere when we
     * deliberately re-feed the same wire fragments after the tick. */
    size_t total = NL_FRAGMENT_CHUNK_SIZE * 2 + 50;
    uint8_t *big = (uint8_t *)malloc(total);
    memset(big, 0xCD, total);
    ASSERT_EQ(nl_channel_send(&chan, /*now_ms*/ 0, 0, NL_UNRELIABLE, big, total, capture_emit, &cap), NL_OK);
    ASSERT_TRUE(cap.count >= 2);

    delivered_t del = {0};
    /* Feed only fragment 0 at t=0: incomplete. */
    nl_channel_on_receive(&chan, 0, cap.packets[0].data, cap.packets[0].len,
                          capture_deliver, &del, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 0);

    /* Tick past NL_REASSEMBLY_TIMEOUT_MS: expire must free the slot. */
    bool give_up = false;
    nl_channel_tick(&chan, 0, NL_REASSEMBLY_TIMEOUT_MS + 100, /*rto_ms*/ 10000, /*max_retries*/ 10,
                    capture_emit, &cap, &give_up);

    /* If expire ran, fragment 0's bookkeeping is gone. Feeding only the
     * LATER fragments must start a fresh, still-incomplete reassembly
     * (del.count stays 0). If expire had NOT run, fragment 0 would still
     * be present and feeding 1..n-1 would complete the message -- which
     * this assertion would catch. */
    for (int i = 1; i < cap.count; i++) {
        nl_channel_on_receive(&chan, /*now_ms*/ NL_REASSEMBLY_TIMEOUT_MS + 100,
                              cap.packets[i].data, cap.packets[i].len,
                              capture_deliver, &del, NULL, NULL, NULL, NULL);
    }
    ASSERT_EQ(del.count, 0); /* slot was reclaimed: still missing fragment 0 */

    /* Now feed fragment 0 as well: fresh reassembly completes correctly. */
    nl_channel_on_receive(&chan, NL_REASSEMBLY_TIMEOUT_MS + 100,
                          cap.packets[0].data, cap.packets[0].len,
                          capture_deliver, &del, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1);
    ASSERT_EQ(del.len[0], (uint32_t)total);
    ASSERT_MEM_EQ(del.data[0], big, total);

    nl_channel_free(&chan);
    free(big);
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
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del, NULL, NULL, NULL, NULL);

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
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
    /* simulate a spurious retransmit/duplicate delivery of the same packet */
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);

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
        nl_channel_on_receive(&receiver, 0, cap.packets[order[i]].data, cap.packets[order[i]].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
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
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1);
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1); /* C withheld, waiting for B */

    /* B finally arrives (e.g. a retransmit) -- both B and C should release. */
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
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
    nl_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 0); /* incomplete + out of order, nothing deliverable */
    nl_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 0);
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);

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
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
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
    nl_channel_on_receive(&receiver, 300, retrans.packets[0].data, retrans.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);
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
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);

    /* Receiver's next send piggybacks an ack for what it received. */
    capture_t ack_cap = {0};
    nl_channel_send(&receiver, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"reply", 5, capture_emit, &ack_cap);
    nl_channel_on_receive(&sender, 0, ack_cap.packets[0].data, ack_cap.packets[0].len, capture_deliver, &del, NULL, NULL, NULL, NULL);

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

TEST(test_rtt_sample_on_clean_ack) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    nl_channel_send(&sender, /*now_ms*/ 1000, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"x", 1, capture_emit, &cap);

    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 1000, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del,
                           NULL, NULL, NULL, NULL);

    capture_t ack_cap = {0};
    nl_channel_send(&receiver, 1000, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, capture_emit, &ack_cap);

    bool has_sample = false;
    uint32_t sample_ms = 0;
    /* The ack for our packet 0 arrives 42ms later. */
    nl_channel_on_receive(&sender, 1042, ack_cap.packets[0].data, ack_cap.packets[0].len, capture_deliver, &del,
                           NULL, NULL, &has_sample, &sample_ms);

    ASSERT_TRUE(has_sample);
    ASSERT_EQ(sample_ms, 42);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_rtt_no_sample_for_retransmitted_packet) {
    /* Karn's algorithm: once a packet has been retransmitted, an ack for
     * it is ambiguous (could be acking the original or the resend), so it
     * must never be used as an RTT sample. */
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    nl_channel_send(&sender, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"x", 1, capture_emit, &cap);

    /* Force a retransmit via nl_channel_tick before any ack arrives. */
    capture_t retrans = {0};
    bool give_up = false;
    nl_channel_tick(&sender, 0, 500, /*rto_ms*/ 200, 10, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 1);

    delivered_t del = {0};
    nl_channel_on_receive(&receiver, 500, retrans.packets[0].data, retrans.packets[0].len, capture_deliver, &del,
                           NULL, NULL, NULL, NULL);
    capture_t ack_cap = {0};
    nl_channel_send(&receiver, 500, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, capture_emit, &ack_cap);

    bool has_sample = true; /* poison: must be set false by the call */
    uint32_t sample_ms = 0;
    nl_channel_on_receive(&sender, 600, ack_cap.packets[0].data, ack_cap.packets[0].len, capture_deliver, &del,
                           NULL, NULL, &has_sample, &sample_ms);

    ASSERT_FALSE(has_sample);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_rtt_no_sample_for_unreliable_lane) {
    /* Unreliable lanes have no send ring / ack tracking at all -- must
     * not crash and must report no sample. */
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};
    nl_channel_send(&sender, 0, 0, NL_UNRELIABLE, (const uint8_t *)"x", 1, capture_emit, &cap);

    delivered_t del = {0};
    bool has_sample = true;
    uint32_t sample_ms = 0;
    nl_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, capture_deliver, &del,
                           NULL, NULL, &has_sample, &sample_ms);
    ASSERT_FALSE(has_sample);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_fast_retransmit_triggers_on_reorder_threshold) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    /* Send 5 packets: 0,1,2,3,4. Packet 0 gets "lost" (never delivered to
     * receiver); 1..4 arrive and get acked, so packet 0 accumulates 4
     * strictly-newer acked packets -- past the threshold of 3. */
    for (int i = 0; i < 5; i++) {
        char msg[2] = { (char)('a' + i), 0 };
        nl_channel_send(&sender, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)msg, 1, capture_emit, &cap);
    }
    ASSERT_EQ(cap.count, 5);

    delivered_t del = {0};
    for (int i = 1; i < 5; i++) {
        nl_channel_on_receive(&receiver, 0, cap.packets[i].data, cap.packets[i].len, capture_deliver, &del,
                               NULL, NULL, NULL, NULL);
    }
    capture_t ack_cap = {0};
    nl_channel_send(&receiver, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, capture_emit, &ack_cap);

    /* Feed that ack back to the sender -- well before RTO would fire --
     * and it should immediately fast-retransmit packet 0. */
    capture_t fast_retrans = {0};
    nl_channel_on_receive(&sender, 10 /* far less than any real RTO */, ack_cap.packets[0].data,
                           ack_cap.packets[0].len, capture_deliver, &del,
                           capture_emit, &fast_retrans, NULL, NULL);

    ASSERT_EQ(fast_retrans.count, 1);
    /* Confirm it's really packet 0's data being retransmitted, by feeding
     * it to a fresh receiver and checking the payload. */
    nl_channel_t fresh_receiver;
    nl_channel_init(&fresh_receiver);
    delivered_t del2 = {0};
    nl_channel_on_receive(&fresh_receiver, 0, fast_retrans.packets[0].data, fast_retrans.packets[0].len,
                           capture_deliver, &del2, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del2.count, 1);
    ASSERT_EQ(del2.data[0][0], 'a');
    nl_channel_free(&fresh_receiver);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_fast_retransmit_does_not_trigger_below_threshold) {
    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);
    capture_t cap = {0};

    /* Send 3 packets: 0,1,2. Packet 0 "lost"; only 1 and 2 arrive -- just
     * 2 strictly-newer acked packets, below the threshold of 3. Ordinary
     * reordering commonly looks exactly like this, so it must NOT trigger
     * a premature retransmit. */
    for (int i = 0; i < 3; i++) {
        char msg[2] = { (char)('a' + i), 0 };
        nl_channel_send(&sender, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)msg, 1, capture_emit, &cap);
    }

    delivered_t del = {0};
    for (int i = 1; i < 3; i++) {
        nl_channel_on_receive(&receiver, 0, cap.packets[i].data, cap.packets[i].len, capture_deliver, &del,
                               NULL, NULL, NULL, NULL);
    }
    capture_t ack_cap = {0};
    nl_channel_send(&receiver, 0, 0, NL_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, capture_emit, &ack_cap);

    capture_t fast_retrans = {0};
    nl_channel_on_receive(&sender, 10, ack_cap.packets[0].data, ack_cap.packets[0].len, capture_deliver, &del,
                           capture_emit, &fast_retrans, NULL, NULL);

    ASSERT_EQ(fast_retrans.count, 0);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

int main(void) {
    printf("=== channel tests ===\n");
    RUN_TEST(test_unreliable_basic_roundtrip);
    RUN_TEST(test_unreliable_sequenced_drops_stale);
    RUN_TEST(test_sequenced_fragmented_reassembles_out_of_order_fragments);
    RUN_TEST(test_channel_tick_expires_stale_reassembly);
    RUN_TEST(test_reliable_unordered_delivers_all_ignores_order);
    RUN_TEST(test_reliable_unordered_dedupes_retransmit);
    RUN_TEST(test_reliable_ordered_delivers_in_order_despite_network_reorder);
    RUN_TEST(test_reliable_ordered_withholds_until_gap_fills);
    RUN_TEST(test_fragmented_reliable_ordered_message);
    RUN_TEST(test_multiple_channels_independent_sequence_spaces);
    RUN_TEST(test_retransmission_on_tick_when_unacked);
    RUN_TEST(test_no_retransmit_after_ack_received);
    RUN_TEST(test_give_up_after_max_retries);
    RUN_TEST(test_rtt_sample_on_clean_ack);
    RUN_TEST(test_rtt_no_sample_for_retransmitted_packet);
    RUN_TEST(test_rtt_no_sample_for_unreliable_lane);
    RUN_TEST(test_fast_retransmit_triggers_on_reorder_threshold);
    RUN_TEST(test_fast_retransmit_does_not_trigger_below_threshold);
    TEST_SUMMARY();
}
