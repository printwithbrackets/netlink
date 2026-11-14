#include "test_framework.h"
#include "../src/channel.h"
#include "../src/byteorder.h"
#include <string.h>
#include <stdlib.h>

/* ---- a tiny in-memory "network" for feeding one channel's emitted
 * packets to another, with the ability to drop/reorder/duplicate ---- */

#define MAX_CAPTURED 512

typedef struct {
    uint8_t data[WN_MAX_PACKET_SIZE];
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

#define WN_MAX_MESSAGE_SIZE_FOR_TEST (16 * 1024) /* keep test stack/struct size sane; we only send small test messages */

typedef struct {
    uint8_t data[8][WN_MAX_MESSAGE_SIZE_FOR_TEST];
    uint32_t len[8];
    uint8_t channel[8];
    wn_delivery_t delivery[8];
    int count;
} delivered_t;

static void capture_deliver(void *ctx, uint8_t channel_id, wn_delivery_t delivery, const uint8_t *data, uint32_t len) {
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
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);

    capture_t cap = {0};
    const char *msg = "hello unreliable";
    wn_result_t r = wn_channel_send(&sender, 1000, 3, WN_UNRELIABLE, (const uint8_t *)msg, strlen(msg), WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    ASSERT_EQ(r, WN_OK);
    ASSERT_EQ(cap.count, 1);

    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 1000, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1);
    ASSERT_EQ(del.channel[0], 3);
    ASSERT_EQ(del.delivery[0], WN_UNRELIABLE);
    ASSERT_EQ(del.len[0], strlen(msg));
    ASSERT_MEM_EQ(del.data[0], msg, strlen(msg));

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_unreliable_sequenced_drops_stale) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    const char *m1 = "position update 1";
    const char *m2 = "position update 2";
    const char *m3 = "position update 3";
    wn_channel_send(&sender, 0, 0, WN_UNRELIABLE_SEQUENCED, (const uint8_t *)m1, strlen(m1), WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    wn_channel_send(&sender, 0, 0, WN_UNRELIABLE_SEQUENCED, (const uint8_t *)m2, strlen(m2), WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    wn_channel_send(&sender, 0, 0, WN_UNRELIABLE_SEQUENCED, (const uint8_t *)m3, strlen(m3), WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    ASSERT_EQ(cap.count, 3);

    /* Simulate network reordering: 3 arrives before 2 (2 gets lost/late) */
    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL); /* m3 */
    wn_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL); /* m2, stale */

    ASSERT_EQ(del.count, 1); /* only m3 delivered; m2 dropped as stale */
    ASSERT_MEM_EQ(del.data[0], m3, strlen(m3));

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

/* Regression: fragmented UNRELIABLE_SEQUENCED messages must not be gated
 * per-fragment on seq_highest_seen -- that would drop the earlier fragment
 * of a reordered pair and strand reassembly incomplete forever. Each
 * fragment must reach reassembly; the stale-drop gate applies only once
 * the whole message is ready to deliver. */
TEST(test_sequenced_fragmented_reassembles_out_of_order_fragments) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    /* >1 fragment so the fragmented sequenced path is taken. */
    size_t total = WN_FRAGMENT_CHUNK_SIZE + 300;
    uint8_t *big = (uint8_t *)malloc(total);
    for (size_t i = 0; i < total; i++) big[i] = (uint8_t)((i * 17 + 3) & 0xFF);

    wn_result_t r = wn_channel_send(&sender, 0, 0, WN_UNRELIABLE_SEQUENCED, big, total, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    ASSERT_EQ(r, WN_OK);
    ASSERT_TRUE(cap.count >= 2); /* at least 2 fragments */

    /* Deliver fragments in reverse arrival order. Before the fix, fragment
     * 0 would be dropped as "stale" relative to a higher sequence already
     * seen from fragment 1, and the message would never reassemble. */
    delivered_t del = {0};
    for (int i = cap.count - 1; i >= 0; i--) {
        wn_channel_on_receive(&receiver, 0, cap.packets[i].data, cap.packets[i].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    ASSERT_EQ(del.count, 1); /* whole message delivered exactly once */
    ASSERT_EQ(del.len[0], (uint32_t)total);
    uint8_t *cmp = (uint8_t *)malloc(total);
    memcpy(cmp, del.data[0], total < sizeof(del.data[0]) ? total : sizeof(del.data[0]));
    ASSERT_TRUE(total <= sizeof(del.data[0]));
    ASSERT_MEM_EQ(cmp, big, total);

    free(cmp);
    free(big);
    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

/* Regression: wn_channel_tick must reclaim stale reassembly slots via
 * wn_reassembly_expire on every lane, not only under eviction pressure.
 * Without this, incomplete messages pinned their slots until the table
 * filled (fragment.h documents tick as the expected caller). */
TEST(test_channel_tick_expires_stale_reassembly) {
    wn_channel_t chan;
    wn_channel_init(&chan);
    capture_t cap = {0};

    /* WN_UNRELIABLE so the sequence-dedupe path doesn't interfere when we
     * deliberately re-feed the same wire fragments after the tick. */
    size_t total = WN_FRAGMENT_CHUNK_SIZE * 2 + 50;
    uint8_t *big = (uint8_t *)malloc(total);
    memset(big, 0xCD, total);
    ASSERT_EQ(wn_channel_send(&chan, /*now_ms*/ 0, 0, WN_UNRELIABLE, big, total, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap), WN_OK);
    ASSERT_TRUE(cap.count >= 2);

    delivered_t del = {0};
    /* Feed only fragment 0 at t=0: incomplete. */
    wn_channel_on_receive(&chan, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 0);

    /* Tick past WN_REASSEMBLY_TIMEOUT_MS: expire must free the slot. */
    bool give_up = false;
    wn_channel_tick(&chan, 0, WN_REASSEMBLY_TIMEOUT_MS + 100, /*rto_ms*/ 10000, /*max_retries*/ 10, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap, &give_up);

    /* If expire ran, fragment 0's bookkeeping is gone. Feeding only the
     * LATER fragments must start a fresh, still-incomplete reassembly
     * (del.count stays 0). If expire had NOT run, fragment 0 would still
     * be present and feeding 1..n-1 would complete the message -- which
     * this assertion would catch. */
    for (int i = 1; i < cap.count; i++) {
        wn_channel_on_receive(&chan, /*now_ms*/ WN_REASSEMBLY_TIMEOUT_MS + 100, cap.packets[i].data, cap.packets[i].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    ASSERT_EQ(del.count, 0); /* slot was reclaimed: still missing fragment 0 */

    /* Now feed fragment 0 as well: fresh reassembly completes correctly. */
    wn_channel_on_receive(&chan, WN_REASSEMBLY_TIMEOUT_MS + 100, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1);
    ASSERT_EQ(del.len[0], (uint32_t)total);
    ASSERT_MEM_EQ(del.data[0], big, total);

    wn_channel_free(&chan);
    free(big);
}

TEST(test_reliable_unordered_delivers_all_ignores_order) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    const char *m1 = "a", *m2 = "b", *m3 = "c";
    wn_channel_send(&sender, 0, 2, WN_RELIABLE_UNORDERED, (const uint8_t *)m1, 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    wn_channel_send(&sender, 0, 2, WN_RELIABLE_UNORDERED, (const uint8_t *)m2, 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    wn_channel_send(&sender, 0, 2, WN_RELIABLE_UNORDERED, (const uint8_t *)m3, 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    delivered_t del = {0};
    /* deliver out of order: 2, 0, 1 */
    wn_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    wn_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);

    ASSERT_EQ(del.count, 3);
    /* delivered in arrival order (unordered mode), so c, a, b */
    ASSERT_EQ(del.data[0][0], 'c');
    ASSERT_EQ(del.data[1][0], 'a');
    ASSERT_EQ(del.data[2][0], 'b');

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_reliable_unordered_dedupes_retransmit) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};
    const char *m = "x";
    wn_channel_send(&sender, 0, 0, WN_RELIABLE_UNORDERED, (const uint8_t *)m, 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    /* simulate a spurious retransmit/duplicate delivery of the same packet */
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);

    ASSERT_EQ(del.count, 1); /* delivered exactly once to the application */

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_reliable_ordered_delivers_in_order_despite_network_reorder) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    const char *msgs[5] = {"one", "two", "three", "four", "five"};
    for (int i = 0; i < 5; i++) {
        wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)msgs[i], strlen(msgs[i]), WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    }
    ASSERT_EQ(cap.count, 5);

    /* Deliver scrambled: 0, 2, 1, 4, 3 */
    int order[5] = {0, 2, 1, 4, 3};
    delivered_t del = {0};
    for (int i = 0; i < 5; i++) {
        wn_channel_on_receive(&receiver, 0, cap.packets[order[i]].data, cap.packets[order[i]].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    ASSERT_EQ(del.count, 5);
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(del.len[i], strlen(msgs[i]));
        ASSERT_MEM_EQ(del.data[i], msgs[i], strlen(msgs[i]));
    }

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_reliable_ordered_withholds_until_gap_fills) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    const char *msgs[3] = {"A", "B", "C"};
    for (int i = 0; i < 3; i++) {
        wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)msgs[i], 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    }

    delivered_t del = {0};
    /* Packet 1 (B) is "lost" for now; deliver 0 (A) then 2 (C). */
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1);
    wn_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1); /* C withheld, waiting for B */

    /* B finally arrives (e.g. a retransmit) -- both B and C should release. */
    wn_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 3);
    ASSERT_EQ(del.data[0][0], 'A');
    ASSERT_EQ(del.data[1][0], 'B');
    ASSERT_EQ(del.data[2][0], 'C');

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_fragmented_reliable_ordered_message) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    size_t total = WN_FRAGMENT_CHUNK_SIZE * 2 + 300;
    uint8_t *big = (uint8_t *)malloc(total);
    for (size_t i = 0; i < total; i++) big[i] = (uint8_t)((i * 13 + 7) & 0xFF);

    wn_result_t r = wn_channel_send(&sender, 0, 5, WN_RELIABLE_ORDERED, big, total, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    ASSERT_EQ(r, WN_OK);
    ASSERT_EQ(cap.count, 3); /* 3 fragments */

    delivered_t del = {0};
    /* deliver fragments out of order */
    wn_channel_on_receive(&receiver, 0, cap.packets[1].data, cap.packets[1].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 0); /* incomplete + out of order, nothing deliverable */
    wn_channel_on_receive(&receiver, 0, cap.packets[2].data, cap.packets[2].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 0);
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);

    ASSERT_EQ(del.count, 1); /* the whole reassembled message delivered as one unit */
    ASSERT_EQ(del.len[0], total);

    /* Compare against a heap buffer since del.data is fixed-size */
    uint8_t *cmp = (uint8_t *)malloc(total);
    memcpy(cmp, del.data[0], total < sizeof(del.data[0]) ? total : sizeof(del.data[0]));
    ASSERT_TRUE(total <= sizeof(del.data[0]));
    ASSERT_MEM_EQ(cmp, big, total);

    free(cmp);
    free(big);
    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_multiple_channels_independent_sequence_spaces) {
    /* Two different channel_ids used on the SAME wn_channel_t instance
     * would collide in real usage (each channel_id gets its own
     * wn_channel_t in connection.c) -- this test instead proves that the
     * channel_id byte is carried through transparently so the layer above
     * can demux by it. */
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    wn_channel_send(&sender, 0, 7, WN_RELIABLE_ORDERED, (const uint8_t *)"chan7", 5, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1);
    ASSERT_EQ(del.channel[0], 7);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_retransmission_on_tick_when_unacked) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    wn_channel_send(&sender, 0 /*now_ms*/, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"retry-me", 8, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    ASSERT_EQ(cap.count, 1);

    /* Not enough time has passed: no retransmit yet. */
    capture_t retrans = {0};
    bool give_up = false;
    wn_channel_tick(&sender, 0, /*now_ms*/ 50, /*rto_ms*/ 200, /*max_retries*/ 10, WN_RECV_WINDOW_DEFAULT, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 0);
    ASSERT_FALSE(give_up);

    /* Past the RTO with no ack received: must retransmit. */
    wn_channel_tick(&sender, 0, /*now_ms*/ 300, 200, 10, WN_RECV_WINDOW_DEFAULT, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 1);
    ASSERT_FALSE(give_up);

    /* The retransmitted packet must still be understood correctly by a receiver. */
    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 300, retrans.packets[0].data, retrans.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 1);
    ASSERT_MEM_EQ(del.data[0], "retry-me", 8);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_no_retransmit_after_ack_received) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"acked", 5, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);

    /* Receiver's next send piggybacks an ack for what it received. */
    capture_t ack_cap = {0};
    wn_channel_send(&receiver, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"reply", 5, WN_RECV_WINDOW_DEFAULT, capture_emit, &ack_cap);
    wn_channel_on_receive(&sender, 0, ack_cap.packets[0].data, ack_cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);

    /* Sender's packet is now acked -- ticking well past RTO must NOT retransmit it. */
    capture_t retrans = {0};
    bool give_up = false;
    wn_channel_tick(&sender, 0, 10000, 200, 10, WN_RECV_WINDOW_DEFAULT, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 0);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_give_up_after_max_retries) {
    wn_channel_t sender;
    wn_channel_init(&sender);
    capture_t cap = {0};
    wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"x", 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    /* Retransmit backoff doubles the base RTO per retry (capped at
     * WN_MAX_BACKOFF_MS), so each retry must jump time by the slot's
     * current backoff, not a flat rto. */
    bool give_up = false;
    capture_t retrans;
    uint64_t t = 0;
    for (uint32_t i = 0; i < 3; i++) {
        t += (uint64_t)200 << i; /* rto=200, retry_count=i -> backoff = 200 << i */
        memset(&retrans, 0, sizeof(retrans));
        wn_channel_tick(&sender, 0, t, 200, /*max_retries*/ 3, WN_RECV_WINDOW_DEFAULT, capture_emit, &retrans, &give_up);
        ASSERT_FALSE(give_up);
    }
    ASSERT_EQ(retrans.count, 1); /* the third retry did fire before give-up */

    /* retry_count==3 == max_retries: once the 200<<3=1600ms backoff
     * elapses, the scan sees a due slot at the retry limit and gives up. */
    t += (uint64_t)200 << 3;
    memset(&retrans, 0, sizeof(retrans));
    wn_channel_tick(&sender, 0, t, 200, 3, WN_RECV_WINDOW_DEFAULT, capture_emit, &retrans, &give_up);
    ASSERT_TRUE(give_up);

    wn_channel_free(&sender);
}

TEST(test_rtt_sample_on_clean_ack) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    wn_channel_send(&sender, /*now_ms*/ 1000, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"x", 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 1000, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);

    capture_t ack_cap = {0};
    wn_channel_send(&receiver, 1000, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, WN_RECV_WINDOW_DEFAULT, capture_emit, &ack_cap);

    bool has_sample = false;
    uint32_t sample_ms = 0;
    /* The ack for our packet 0 arrives 42ms later. */
    wn_channel_on_receive(&sender, 1042, ack_cap.packets[0].data, ack_cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, &has_sample, &sample_ms, NULL, NULL);

    ASSERT_TRUE(has_sample);
    ASSERT_EQ(sample_ms, 42);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_rtt_no_sample_for_retransmitted_packet) {
    /* Karn's algorithm: once a packet has been retransmitted, an ack for
     * it is ambiguous (could be acking the original or the resend), so it
     * must never be used as an RTT sample. */
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"x", 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    /* Force a retransmit via wn_channel_tick before any ack arrives. */
    capture_t retrans = {0};
    bool give_up = false;
    wn_channel_tick(&sender, 0, 500, /*rto_ms*/ 200, 10, WN_RECV_WINDOW_DEFAULT, capture_emit, &retrans, &give_up);
    ASSERT_EQ(retrans.count, 1);

    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 500, retrans.packets[0].data, retrans.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    capture_t ack_cap = {0};
    wn_channel_send(&receiver, 500, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, WN_RECV_WINDOW_DEFAULT, capture_emit, &ack_cap);

    bool has_sample = true; /* poison: must be set false by the call */
    uint32_t sample_ms = 0;
    wn_channel_on_receive(&sender, 600, ack_cap.packets[0].data, ack_cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, &has_sample, &sample_ms, NULL, NULL);

    ASSERT_FALSE(has_sample);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_rtt_no_sample_for_unreliable_lane) {
    /* Unreliable lanes have no send ring / ack tracking at all -- must
     * not crash and must report no sample. */
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};
    wn_channel_send(&sender, 0, 0, WN_UNRELIABLE, (const uint8_t *)"x", 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);

    delivered_t del = {0};
    bool has_sample = true;
    uint32_t sample_ms = 0;
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, &has_sample, &sample_ms, NULL, NULL);
    ASSERT_FALSE(has_sample);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_fast_retransmit_triggers_on_reorder_threshold) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    /* Send 5 packets: 0,1,2,3,4. Packet 0 gets "lost" (never delivered to
     * receiver); 1..4 arrive and get acked, so packet 0 accumulates 4
     * strictly-newer acked packets -- past the threshold of 3. */
    for (int i = 0; i < 5; i++) {
        char msg[2] = { (char)('a' + i), 0 };
        wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)msg, 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    }
    ASSERT_EQ(cap.count, 5);

    delivered_t del = {0};
    for (int i = 1; i < 5; i++) {
        wn_channel_on_receive(&receiver, 0, cap.packets[i].data, cap.packets[i].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    capture_t ack_cap = {0};
    wn_channel_send(&receiver, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, WN_RECV_WINDOW_DEFAULT, capture_emit, &ack_cap);

    /* Feed that ack back to the sender -- well before RTO would fire --
     * and it should immediately fast-retransmit packet 0. */
    capture_t fast_retrans = {0};
    wn_channel_on_receive(&sender, 10 /* far less than any real RTO */, ack_cap.packets[0].data, ack_cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, capture_emit, &fast_retrans, NULL, NULL, NULL, NULL);

    ASSERT_EQ(fast_retrans.count, 1);
    /* Confirm it's really packet 0's data being retransmitted, by feeding
     * it to a fresh receiver and checking the payload. */
    wn_channel_t fresh_receiver;
    wn_channel_init(&fresh_receiver);
    delivered_t del2 = {0};
    wn_channel_on_receive(&fresh_receiver, 0, fast_retrans.packets[0].data, fast_retrans.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del2, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del2.count, 1);
    ASSERT_EQ(del2.data[0][0], 'a');
    wn_channel_free(&fresh_receiver);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

TEST(test_fast_retransmit_does_not_trigger_below_threshold) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    /* Send 3 packets: 0,1,2. Packet 0 "lost"; only 1 and 2 arrive -- just
     * 2 strictly-newer acked packets, below the threshold of 3. Ordinary
     * reordering commonly looks exactly like this, so it must NOT trigger
     * a premature retransmit. */
    for (int i = 0; i < 3; i++) {
        char msg[2] = { (char)('a' + i), 0 };
        wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)msg, 1, WN_RECV_WINDOW_DEFAULT, capture_emit, &cap);
    }

    delivered_t del = {0};
    for (int i = 1; i < 3; i++) {
        wn_channel_on_receive(&receiver, 0, cap.packets[i].data, cap.packets[i].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    capture_t ack_cap = {0};
    wn_channel_send(&receiver, 0, 0, WN_RELIABLE_ORDERED, (const uint8_t *)"ack", 3, WN_RECV_WINDOW_DEFAULT, capture_emit, &ack_cap);

    capture_t fast_retrans = {0};
    wn_channel_on_receive(&sender, 10, ack_cap.packets[0].data, ack_cap.packets[0].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, &del, capture_emit, &fast_retrans, NULL, NULL, NULL, NULL);

    ASSERT_EQ(fast_retrans.count, 0);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

/* Regression: wn_reorder_ring_insert's return value was discarded, and the
 * dedupe insert that precedes it recorded the sequence regardless. A packet
 * so far ahead of next_expected that the reorder ring drops it was therefore
 * acked: the sender stopped retransmitting it, while next_expected sat
 * behind the gap forever, withholding every later message with it. */
TEST(test_packet_beyond_reorder_window_is_dropped_not_acked) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    capture_t cap = {0};

    /* Sequence 0, so the wire layout is the real one; then rewrite the
     * sequence field to something far beyond any receiver's reorder window
     * (WN_SEQ_RING_SIZE). Going through the real encoder keeps the header
     * layout honest -- the send ring itself can only hold 256 packets, so a
     * genuinely far-ahead sequence can't be produced by sending. */
    uint8_t payload[4] = { 'x', 0, 0, 0 };
    ASSERT_EQ(wn_channel_send(&sender, 0, 0, WN_RELIABLE_ORDERED, payload, sizeof(payload),
                              WN_RECV_WINDOW_DEFAULT, capture_emit, &cap), WN_OK);
    ASSERT_EQ(cap.count, 1);
    const uint16_t far_seq = WN_SEQ_RING_SIZE + 40;
    wn_put_u16(cap.packets[0].data + 2, far_seq);

    delivered_t del = {0};
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len,
                          WN_RECV_WINDOW_DEFAULT, capture_deliver, &del,
                          NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del.count, 0);

    wn_lane_t *lane = &receiver.lanes[WN_RELIABLE_ORDERED];
    /* It must not be recorded as received: an ack covering it would stop the
     * sender retransmitting a packet this lane will never deliver, and
     * next_expected would sit behind the gap forever, withholding every
     * later message. A fresh insert succeeding proves the dedupe never saw
     * it. */
    ASSERT_TRUE(wn_recv_dedupe_insert(&lane->recv_dedupe, far_seq));
    ASSERT_EQ(lane->reorder_ring.next_expected, 0);

    /* The lane is still usable: a real in-order stream from 0 delivers
     * normally. */
    wn_channel_t s2, r2;
    wn_channel_init(&s2);
    wn_channel_init(&r2);
    capture_t cap2 = {0};
    const int n = 8; /* delivered_t holds 8 payloads */
    for (int i = 0; i < n; i++) {
        uint8_t b = (uint8_t)i;
        ASSERT_EQ(wn_channel_send(&s2, 0, 0, WN_RELIABLE_ORDERED, &b, 1,
                                  WN_RECV_WINDOW_DEFAULT, capture_emit, &cap2), WN_OK);
    }
    delivered_t del2 = {0};
    for (int i = 0; i < n; i++) {
        wn_channel_on_receive(&r2, 10, cap2.packets[i].data, cap2.packets[i].len,
                              WN_RECV_WINDOW_DEFAULT, capture_deliver, &del2,
                              NULL, NULL, NULL, NULL, NULL, NULL);
    }
    ASSERT_EQ(del2.count, n);
    for (int i = 0; i < n; i++) ASSERT_EQ(del2.data[i][0], (uint8_t)i);

    wn_channel_free(&s2);
    wn_channel_free(&r2);
    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

/* Regression: a reliable lane that has received NOTHING still used to stamp
 * ack=0/ack_bits=0 into its DATA header -- a valid on-the-wire encoding of
 * "I have sequence 0". The receiver applies acks unconditionally for
 * reliable lanes, so a peer that sent seq 0 and had it lost would see its
 * seq 0 silently marked acked by this bogus ack: it never retransmits and
 * its reorder ring waits forever. The ack is now tagged with an
 * ack_valid bit, and a "no ack yet" encoding must be distinguishable. */
TEST(test_no_ack_from_empty_lane_does_not_ack_peer_seq_zero) {
    wn_channel_t A, B;
    wn_channel_init(&A);
    wn_channel_init(&B);

    /* B sends one RELIABLE_ORDERED packet (its sequence 0). Dropped. */
    uint8_t p[4] = {1, 2, 3, 4};
    capture_t b_cap = {0};
    ASSERT_EQ(wn_channel_send(&B, 0, 0, WN_RELIABLE_ORDERED, p, sizeof(p),
                              WN_RECV_WINDOW_DEFAULT, capture_emit, &b_cap), WN_OK);
    ASSERT_EQ(b_cap.count, 1);
    ASSERT_EQ(B.lanes[WN_RELIABLE_ORDERED].send_ring.unacked_count, 1);

    /* A's lane has never received anything, so its outgoing reliable
     * packet carries "no ack" -- which must arrive at B as such. */
    capture_t a_cap = {0};
    ASSERT_EQ(wn_channel_send(&A, 10, 0, WN_RELIABLE_ORDERED, p, sizeof(p),
                              WN_RECV_WINDOW_DEFAULT, capture_emit, &a_cap), WN_OK);
    ASSERT_EQ(a_cap.count, 1);
    ASSERT_FALSE(A.lanes[WN_RELIABLE_ORDERED].recv_dedupe_init);

    delivered_t del = {0};
    bool has_sample = false;
    uint32_t sample_ms = 0;
    uint32_t newly = 99;
    wn_channel_on_receive(&B, 20, a_cap.packets[0].data, a_cap.packets[0].len,
                          WN_RECV_WINDOW_DEFAULT, capture_deliver, &del,
                          NULL, NULL, &has_sample, &sample_ms, &newly, NULL);
    ASSERT_EQ(del.count, 1); /* A's own message delivered fine */

    /* B's lost sequence 0 must still be awaiting retransmission. */
    ASSERT_EQ(B.lanes[WN_RELIABLE_ORDERED].send_ring.unacked_count, 1);
    ASSERT_EQ(newly, 0);
    ASSERT_FALSE(has_sample);

    wn_channel_free(&A);
    wn_channel_free(&B);
}

TEST(test_rwnd_carried_on_data_header) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);

    /* Sender stamps its local window; receiver must parse it back out. */
    capture_t cap = {0};
    uint16_t local = 12345;
    ASSERT_EQ(wn_channel_send(&sender, 0, 0, WN_UNRELIABLE, (const uint8_t *)"z", 1, local,
                               capture_emit, &cap), WN_OK);
    ASSERT_EQ(cap.count, 1);

    delivered_t del = {0};
    uint16_t peer_rwnd = 0;
    uint32_t newly = 99;
    wn_channel_on_receive(&receiver, 0, cap.packets[0].data, cap.packets[0].len, WN_RECV_WINDOW_DEFAULT,
                           capture_deliver, &del, NULL, NULL, NULL, NULL, &newly, &peer_rwnd);
    ASSERT_EQ(peer_rwnd, local);
    ASSERT_EQ(del.count, 1);

    wn_channel_free(&sender);
    wn_channel_free(&receiver);
}

/* Regression: wn_channel_send_range's ring-full path reported
 * *out_sent_frags = i, but the loop counts from start_frag, so on a
 * continuation send it over-reported by start_frag -- claiming fragments it
 * never emitted. The caller (connection.c's flush_deferred) turns that into
 * a continuation parked at the wrong frag_start, silently skipping that many
 * fragments of the message. */
TEST(test_partial_send_reports_fragments_actually_sent) {
    wn_channel_t chan;
    wn_channel_init(&chan);
    capture_t cap = {0};

    /* Fill the send ring completely so the next insert is refused. */
    for (int i = 0; i < WN_SEQ_RING_SIZE; i++) {
        uint8_t b = (uint8_t)i;
        ASSERT_EQ(wn_channel_send(&chan, 0, 0, WN_RELIABLE_ORDERED, &b, 1,
                                  WN_RECV_WINDOW_DEFAULT, capture_emit, &cap), WN_OK);
    }
    ASSERT_EQ(cap.count, WN_SEQ_RING_SIZE);

    /* A 20-fragment message, attempted as a continuation starting at
     * fragment 10: the very first insert is refused (ring full). */
    size_t total = WN_FRAGMENT_CHUNK_SIZE * 20;
    uint8_t *big = (uint8_t *)malloc(total);
    ASSERT_TRUE(big != NULL);
    memset(big, 'B', total);

    uint16_t message_id = 12345;
    uint16_t sent = 99, frag_count = 0;
    ASSERT_EQ(wn_channel_send_range(&chan, 0, 0, WN_RELIABLE_ORDERED, big, total,
                                    WN_RECV_WINDOW_DEFAULT, /*start_frag*/ 10,
                                    /*max_frags*/ 0, &message_id, capture_emit, &cap,
                                    &sent, &frag_count), WN_OK);
    ASSERT_EQ(frag_count, 20);
    /* Zero fragments went out. Reporting `i` (== 10) here would park a
     * continuation at fragment 20 -- i.e. skip fragments 10..19 of a
     * message the app still expects whole. */
    ASSERT_EQ(sent, 0);
    ASSERT_EQ(cap.count, WN_SEQ_RING_SIZE); /* and nothing was emitted */

    free(big);
    wn_channel_free(&chan);
}


/* Regression: a RELIABLE_UNORDERED fragment that reassembly cannot take yet
 * (byte budget full) used to be recorded in the dedupe window and therefore
 * acked, so the sender stopped retransmitting it and the message was lost
 * for good. It must be left unacked so the retransmit path delivers it. */
TEST(test_reliable_unordered_fragment_not_acked_when_reassembly_full) {
    wn_channel_t sender, receiver;
    wn_channel_init(&sender);
    wn_channel_init(&receiver);
    /* Room for message A (4 fragments) plus 2 more fragments, but not for B (3). */
    wn_channel_set_reassembly_budget(&receiver, 6 * WN_FRAGMENT_CHUNK_SIZE);

    size_t a_len = 4 * WN_FRAGMENT_CHUNK_SIZE;
    size_t b_len = 2 * WN_FRAGMENT_CHUNK_SIZE + 1;
    uint8_t *a = (uint8_t *)malloc(a_len);
    uint8_t *b = (uint8_t *)malloc(b_len);
    memset(a, 0xA1, a_len);
    memset(b, 0xB2, b_len);

    capture_t *cap_a = (capture_t *)calloc(1, sizeof(capture_t));
    capture_t *cap_b = (capture_t *)calloc(1, sizeof(capture_t));
    ASSERT_EQ(wn_channel_send(&sender, 0, 0, WN_RELIABLE_UNORDERED, a, a_len, WN_RECV_WINDOW_DEFAULT, capture_emit, cap_a), WN_OK);
    ASSERT_EQ(wn_channel_send(&sender, 0, 0, WN_RELIABLE_UNORDERED, b, b_len, WN_RECV_WINDOW_DEFAULT, capture_emit, cap_b), WN_OK);
    ASSERT_EQ(cap_a->count, 4);
    ASSERT_EQ(cap_b->count, 3);

    delivered_t *del = (delivered_t *)calloc(1, sizeof(delivered_t));
    /* A arrives minus fragment 1 (lost in transit). */
    for (int i = 0; i < cap_a->count; i++) {
        if (i == 1) continue;
        wn_channel_on_receive(&receiver, 0, cap_a->packets[i].data, cap_a->packets[i].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, del, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    /* B arrives whole, but A still holds 4 of the 6 budgeted fragments. */
    for (int i = 0; i < cap_b->count; i++) {
        wn_channel_on_receive(&receiver, 0, cap_b->packets[i].data, cap_b->packets[i].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, del, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    ASSERT_EQ(del->count, 0);

    /* B's sequences (4..6) must not be covered by the ack the receiver would send:
     * the newest acked sequence is A's last fragment (3). */
    uint16_t ack = 0;
    wn_ack_bits_t bits = 0;
    wn_recv_dedupe_build_ack(&receiver.lanes[WN_RELIABLE_UNORDERED].recv_dedupe, &ack, &bits);
    ASSERT_EQ(ack, 3);

    /* A's missing fragment is retransmitted: A completes and frees its budget. */
    wn_channel_on_receive(&receiver, 0, cap_a->packets[1].data, cap_a->packets[1].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, del, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(del->count, 1);
    ASSERT_EQ(del->len[0], (uint32_t)a_len);

    /* B's fragments are retransmitted and now go through. */
    for (int i = 0; i < cap_b->count; i++) {
        wn_channel_on_receive(&receiver, 0, cap_b->packets[i].data, cap_b->packets[i].len, WN_RECV_WINDOW_DEFAULT, capture_deliver, del, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    ASSERT_EQ(del->count, 2);
    ASSERT_EQ(del->len[1], (uint32_t)b_len);
    ASSERT_MEM_EQ(del->data[1], b, b_len);

    free(a); free(b); free(cap_a); free(cap_b); free(del);
    wn_channel_free(&sender);
    wn_channel_free(&receiver);
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
    RUN_TEST(test_no_ack_from_empty_lane_does_not_ack_peer_seq_zero);
    RUN_TEST(test_packet_beyond_reorder_window_is_dropped_not_acked);
    RUN_TEST(test_partial_send_reports_fragments_actually_sent);
    RUN_TEST(test_rwnd_carried_on_data_header);
    RUN_TEST(test_reliable_unordered_fragment_not_acked_when_reassembly_full);
    TEST_SUMMARY();
}
