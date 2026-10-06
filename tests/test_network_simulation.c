/* test_network_simulation.c - a simulated "bad network" (configurable
 * packet loss, jitter/reordering, and duplication) driving the channel
 * layer through thousands of messages, verifying that RELIABLE_ORDERED
 * delivery is still complete, correctly ordered, and content-correct
 * under conditions real localhost testing never exercises. This is
 * exactly the class of bug "perfect localhost networking politely
 * hides" -- see the project's CROSS_LANGUAGE_TESTING/README notes.
 *
 * This operates at the channel.c level (no sockets, no encryption) so it
 * can run thousands of iterations quickly and deterministically (a fixed
 * PRNG seed) while still exercising the real reliability/ordering/
 * retransmission code paths unmodified.
 */
#include "test_framework.h"
#include "../src/channel.h"
#include <string.h>
#include <stdlib.h>

/* ---- small deterministic PRNG (xorshift32) so runs are reproducible ---- */
static uint32_t g_rng_state;
static void rng_seed(uint32_t seed) { g_rng_state = seed ? seed : 1; }
static uint32_t rng_next(void) {
    uint32_t x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state = x;
    return x;
}
/* Returns true with probability percent/100. */
static bool rng_chance(int percent) {
    return (int)(rng_next() % 100) < percent;
}
static uint32_t rng_range(uint32_t lo, uint32_t hi_inclusive) {
    return lo + (rng_next() % (hi_inclusive - lo + 1));
}

/* ---- simulated network: a queue of in-flight packets, each becoming
 * deliverable at a randomized future virtual tick, with configurable
 * loss and duplication probabilities. ---- */

#define SIM_MAX_INFLIGHT 4096
#define SIM_MAX_PACKET 1536

typedef struct {
    bool active;
    uint32_t deliver_at_tick;
    uint16_t len;
    uint8_t data[SIM_MAX_PACKET];
} sim_packet_t;

typedef struct {
    sim_packet_t packets[SIM_MAX_INFLIGHT];
    int count;
    int loss_percent;
    int duplicate_percent;
    uint32_t min_delay_ticks;
    uint32_t max_delay_ticks;
    /* Scripted loss: drop the FIRST transmission of each sequence in
     * [burst_start, burst_start + burst_len) so a deterministic run can
     * reproduce a specific loss pattern on top of the random background
     * loss. Sequences are read from the wire payload (these tests send a
     * u32 index); only the FIRST copy of each is lost, so the
     * retransmission still gets through -- the burst tests recovery, not
     * permanent loss. */
    uint32_t burst_start;
    uint32_t burst_len;
    uint32_t burst_drops[64];
} sim_network_t;

static void sim_network_init(sim_network_t *net, int loss_percent, int duplicate_percent,
                              uint32_t min_delay_ticks, uint32_t max_delay_ticks) {
    memset(net, 0, sizeof(*net));
    net->loss_percent = loss_percent;
    net->duplicate_percent = duplicate_percent;
    net->min_delay_ticks = min_delay_ticks;
    net->max_delay_ticks = max_delay_ticks;
}

static void sim_network_enqueue_one(sim_network_t *net, const uint8_t *data, uint16_t len, uint32_t now_tick) {
    ASSERT_TRUE(net->count < SIM_MAX_INFLIGHT);
    ASSERT_TRUE(len <= SIM_MAX_PACKET);
    sim_packet_t *p = &net->packets[net->count++];
    p->active = true;
    p->len = len;
    memcpy(p->data, data, len);
    p->deliver_at_tick = now_tick + rng_range(net->min_delay_ticks, net->max_delay_ticks);
}

/* Called from channel.c's emit callback: decide loss/duplication, then enqueue. */
static void sim_network_send(sim_network_t *net, const uint8_t *data, uint16_t len, uint32_t now_tick) {
    if (net->burst_len && len >= NL_DATA_HEADER_SIZE + sizeof(uint32_t)) {
        /* The message body starts right after the header, which already ends
         * with its is_fragment marker -- so the u32 index is at
         * NL_DATA_HEADER_SIZE, not +1. */
        const uint8_t *payload = data + NL_DATA_HEADER_SIZE;
        uint32_t seq;
        memcpy(&seq, payload, sizeof(seq));
        if (seq >= net->burst_start && seq < net->burst_start + net->burst_len) {
            uint32_t idx = seq - net->burst_start;
            if (idx < (uint32_t)(sizeof(net->burst_drops) / sizeof(net->burst_drops[0])) &&
                net->burst_drops[idx] < 1) {
                net->burst_drops[idx] = 1; /* lose this sequence's FIRST copy only */
                return;
            }
        }
    }
    if (rng_chance(net->loss_percent)) return; /* dropped, never enqueued */
    sim_network_enqueue_one(net, data, len, now_tick);
    if (rng_chance(net->duplicate_percent)) {
        sim_network_enqueue_one(net, data, len, now_tick); /* a second, independently-delayed copy */
    }
}

/* Deliver every packet whose time has come, in RANDOM order among those
 * ready (simulating reordering), to `receiver`. */
static void sim_network_deliver_ready(sim_network_t *net, uint32_t now_tick, nl_channel_t *receiver,
                                       nl_channel_deliver_fn deliver, void *deliver_ctx) {
    int ready_idx[SIM_MAX_INFLIGHT];
    int ready_count = 0;
    for (int i = 0; i < net->count; i++) {
        if (net->packets[i].active && net->packets[i].deliver_at_tick <= now_tick) {
            ready_idx[ready_count++] = i;
        }
    }
    while (ready_count > 0) {
        int pick = (int)(rng_next() % (uint32_t)ready_count);
        int idx = ready_idx[pick];
        ready_idx[pick] = ready_idx[ready_count - 1];
        ready_count--;

        sim_packet_t *p = &net->packets[idx];
        p->active = false;
        nl_channel_on_receive(receiver, now_tick, p->data, p->len, NL_RECV_WINDOW_DEFAULT,
                              deliver, deliver_ctx, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    int w = 0;
    for (int i = 0; i < net->count; i++) {
        if (net->packets[i].active) net->packets[w++] = net->packets[i];
    }
    net->count = w;
}

/* ---- receiver-side collection for verification ---- */

#define MAX_RECEIVED 20000
typedef struct {
    uint32_t received[MAX_RECEIVED]; /* each message's payload is a u32 index, for easy verification */
    int count;
} received_log_t;

static void collect_deliver(void *ctx, uint8_t channel_id, nl_delivery_t delivery, const uint8_t *data, uint32_t len) {
    (void)channel_id;
    (void)delivery;
    received_log_t *log = (received_log_t *)ctx;
    ASSERT_EQ(len, (uint32_t)sizeof(uint32_t));
    ASSERT_TRUE(log->count < MAX_RECEIVED);
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    log->received[log->count++] = value;
}

typedef struct {
    sim_network_t *net;
    uint32_t *now_tick;
} emit_ctx_t;

static void emit_to_network(void *ctx, const uint8_t *data, uint16_t len) {
    emit_ctx_t *e = (emit_ctx_t *)ctx;
    sim_network_send(e->net, data, len, *e->now_tick);
}

/* ---- the stress test itself ---- */

/* Packets offered per tick. Large enough that in-flight routinely exceeds
 * NL_ACK_WINDOW_BITS, so the run reaches steady states a trickle can't. */
#define SEND_BURST 64

static void run_reliability_stress_test(const char *name, uint32_t seed, int message_count,
                                         int loss_percent, int duplicate_percent,
                                         uint32_t min_delay_ticks, uint32_t max_delay_ticks,
                                         uint32_t rto_ticks, uint32_t max_ticks) {
    rng_seed(seed);

    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);

    sim_network_t net;
    sim_network_init(&net, loss_percent, duplicate_percent, min_delay_ticks, max_delay_ticks);

    received_log_t log;
    memset(&log, 0, sizeof(log));

    uint32_t now_tick = 0;
    emit_ctx_t ectx = { &net, &now_tick };

    int next_to_send = 0;
    uint32_t tick;
    for (tick = 0; tick < max_ticks; tick++) {
        now_tick = tick;

        /* Burst-send, not one-per-tick. One packet per tick kept in-flight
         * around ~10 forever, which is precisely the regime where the
         * ack-window bugs (a 32-bit bitmap vs a 64-packet congestion
         * window) and the fast-retransmit storm (every advancing ack
         * horizon re-firing the same hole) cannot happen. Real applications
         * fill the window as fast as it opens, so SEND_BURST per tick with
         * the ring's own refusal as the backstop. */
        for (int b = 0; b < SEND_BURST && next_to_send < message_count; b++) {
            /* Hold in-flight at the ack window, which is exactly what
             * connection.c's congestion window does in the real stack: an
             * ack names at most NL_ACK_WINDOW_BITS sequences back from the
             * receiver's newest one, so a deeper flight would strand the
             * oldest packets unackable (which is the bug this sim exists to
             * catch -- but at this layer the invariant is the caller's
             * responsibility, since congestion control lives above).
             * Bursts still reach that window within a few ticks, which the
             * old one-per-tick pacing never did. */
            nl_lane_t *slane = &sender.lanes[NL_RELIABLE_ORDERED];
            if (slane->send_ring_init) {
                /* Gate on the SPAN from the oldest unacked sequence, not the
                 * count: an ack names sequences by position relative to the
                 * receiver's newest one, so count can look small while the
                 * oldest packet sits far out of every future ack's reach.
                 * (Same reason connection.c's congestion window measures the
                 * span -- see reliable_in_flight().) */
                uint16_t oldest = nl_send_ring_oldest_unacked(&slane->send_ring);
                uint16_t span = (uint16_t)(slane->send_ring.next_sequence - oldest);
                if (span >= NL_ACK_WINDOW_BITS) break;
            }
            uint32_t payload = (uint32_t)next_to_send;
            nl_result_t r = nl_channel_send(&sender, now_tick, /*channel_id*/ 0, NL_RELIABLE_ORDERED,
                                             (const uint8_t *)&payload, sizeof(payload),
                                             NL_RECV_WINDOW_DEFAULT, emit_to_network, &ectx);
            if (r != NL_OK) break;
            next_to_send++;
        }

        sim_network_deliver_ready(&net, now_tick, &receiver, collect_deliver, &log);

        /* Hand the receiver's cumulative ack state back to the sender --
         * the channel layer only carries acks piggybacked on outgoing
         * DATA, and this one-way sim has no reverse application traffic.
         * Stand-in for reverse-path DATA/ACK packets: subject to the same
         * loss as everything else. If an ack batch is "lost", the next
         * retransmit sets ack_dirty again (even for duplicates) and a
         * later batch is cumulative, so nothing is permanently stranded.
         */
        nl_lane_t *rlane = &receiver.lanes[NL_RELIABLE_ORDERED];
        if (rlane->ack_dirty && rlane->recv_dedupe_init) {
            if (!rng_chance(net.loss_percent)) {
                uint16_t ack;
                nl_ack_bits_t ack_bits;
                nl_recv_dedupe_build_ack(&rlane->recv_dedupe, &ack, &ack_bits);
                nl_channel_apply_ack(&sender, now_tick, 0, NL_RELIABLE_ORDERED,
                                     /*ack_valid*/ true, ack, ack_bits, NL_RECV_WINDOW_DEFAULT,
                                     emit_to_network, &ectx, NULL, NULL, NULL);
            }
            rlane->ack_dirty = false;
        }

        /* Retransmission scan, using a fixed small RTO in virtual ticks.
         * max_retries is the REAL production bound (NL_MAX_RETRIES, 15)
         * rather than an inflated one: this test asserts give_up never
         * happens, and with a 1000-retry budget that assertion was close to
         * vacuous -- it could not have caught a connection torn down by
         * retry exhaustion, which is exactly how the ack-window bug killed
         * connections. Recovery here relies on the cumulative ack, not on
         * surviving enormous loss, so 15 is plenty for 20% loss with a
         * 4-20x backoff. */
        bool give_up = false;
        nl_channel_tick(&sender, /*channel_id*/ 0, now_tick, rto_ticks, /*max_retries*/ 15,
                        NL_RECV_WINDOW_DEFAULT, emit_to_network, &ectx, &give_up);
        if (give_up) {
            printf("    [%s] sender gave up at tick %u (sent %d/%d delivered %d)\n",
                   name, tick, next_to_send, message_count, log.count);
        }
        ASSERT_FALSE(give_up); /* must never give up within this test's bounds */

        if (next_to_send >= message_count && log.count >= message_count) {
            break; /* everything sent and everything delivered -- done early */
        }
    }

    if (log.count < message_count) {
        printf("    [%s] only %d/%d delivered after %u ticks (loss=%d%% dup=%d%%)\n",
               name, log.count, message_count, tick, loss_percent, duplicate_percent);
    }
    ASSERT_EQ(log.count, message_count); /* nothing permanently lost */

    /* RELIABLE_ORDERED must mean exactly that: strictly increasing, no
     * gaps, no duplicates delivered to the application. */
    for (int i = 0; i < message_count; i++) {
        if (log.received[i] != (uint32_t)i) {
            printf("    [%s] out-of-order/incorrect at position %d: got %u, expected %u\n",
                   name, i, log.received[i], (uint32_t)i);
        }
        ASSERT_EQ(log.received[i], (uint32_t)i);
    }

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_network_sim_moderate_loss_and_reorder) {
    /* 5% loss, 3% duplication, 0-3 tick jitter -- roughly the conditions
     * cited in the project's own review notes as a good stress target. */
    run_reliability_stress_test("moderate", 12345, /*messages*/ 2000,
                                 /*loss*/ 5, /*dup*/ 3, /*delay*/ 0, 3,
                                 /*rto_ticks*/ 8, /*max_ticks*/ 20000);
}

TEST(test_network_sim_heavy_loss) {
    /* Much harsher loss (20%) -- still must eventually deliver everything,
     * in order, given enough retransmission attempts and ticks. */
    run_reliability_stress_test("heavy_loss", 999, /*messages*/ 1000,
                                 /*loss*/ 20, /*dup*/ 1, /*delay*/ 0, 2,
                                 /*rto_ticks*/ 6, /*max_ticks*/ 40000);
}

TEST(test_network_sim_heavy_reorder_and_duplication) {
    /* Low loss but severe reordering (wide delay window) and heavy
     * duplication -- stresses the reorder buffer and dedupe logic rather
     * than retransmission. */
    run_reliability_stress_test("reorder_dup", 424242, /*messages*/ 1500,
                                 /*loss*/ 1, /*dup*/ 25, /*delay*/ 0, 20,
                                 /*rto_ticks*/ 10, /*max_ticks*/ 20000);
}

/* A deterministic loss burst of >=8 consecutive packets while the window is
 * full -- the end-to-end version of the ack-window test in test_seqbuf.c.
 * Everything the burst touches is inside one ack window, so the run must
 * recover completely, and the connection (here: the lane) must survive with
 * nothing left unacked. */
TEST(test_network_sim_sustained_burst_loss_at_full_window) {
    rng_seed(777);

    nl_channel_t sender, receiver;
    nl_channel_init(&sender);
    nl_channel_init(&receiver);

    sim_network_t net;
    /* 1% background loss so the run isn't sterile, plus the scripted burst. */
    sim_network_init(&net, 1, 2, /*min_delay*/ 0, /*max_delay*/ 4);

    received_log_t log;
    memset(&log, 0, sizeof(log));

    uint32_t now_tick = 0;
    emit_ctx_t ectx = { &net, &now_tick };

    const uint32_t burst_start = 40; /* sequence at which loss begins */
    const uint32_t burst_len = 12;   /* >= 8 consecutive */
    const int total = 400;
    net.burst_start = burst_start;
    net.burst_len = burst_len;

    int next_to_send = 0;
    uint16_t peak_span = 0;
    uint32_t tick;
    for (tick = 0; tick < 20000; tick++) {
        now_tick = tick;

        for (int b = 0; b < SEND_BURST && next_to_send < total; b++) {
            nl_lane_t *slane = &sender.lanes[NL_RELIABLE_ORDERED];
            if (slane->send_ring_init) {
                uint16_t oldest = nl_send_ring_oldest_unacked(&slane->send_ring);
                uint16_t span = (uint16_t)(slane->send_ring.next_sequence - oldest);
                if (span >= NL_ACK_WINDOW_BITS) break;
            }
            uint32_t payload = (uint32_t)next_to_send;
            nl_result_t r = nl_channel_send(&sender, now_tick, 0, NL_RELIABLE_ORDERED,
                                             (const uint8_t *)&payload, sizeof(payload),
                                             NL_RECV_WINDOW_DEFAULT, emit_to_network, &ectx);
            if (r != NL_OK) break;
            next_to_send++;
            /* Track the deepest flight reached, so the test can assert the
             * burst really happened at a full window (measured during the
             * run -- at the end everything is acked and the span is 0). */
            uint16_t sp = (uint16_t)(slane->send_ring.next_sequence -
                                     nl_send_ring_oldest_unacked(&slane->send_ring));
            if (sp > peak_span) peak_span = sp;
        }

        sim_network_deliver_ready(&net, now_tick, &receiver, collect_deliver, &log);

        /* Reverse-path acks, same stand-in as the stress test. */
        nl_lane_t *rlane = &receiver.lanes[NL_RELIABLE_ORDERED];
        if (rlane->ack_dirty && rlane->recv_dedupe_init) {
            if (!rng_chance(net.loss_percent)) {
                uint16_t ack;
                nl_ack_bits_t ack_bits;
                nl_recv_dedupe_build_ack(&rlane->recv_dedupe, &ack, &ack_bits);
                nl_channel_apply_ack(&sender, now_tick, 0, NL_RELIABLE_ORDERED,
                                     /*ack_valid*/ true, ack, ack_bits, NL_RECV_WINDOW_DEFAULT,
                                     emit_to_network, &ectx, NULL, NULL, NULL);
            }
            rlane->ack_dirty = false;
        }

        bool give_up = false;
        nl_channel_tick(&sender, 0, now_tick, /*rto_ticks*/ 8, /*max_retries*/ 15,
                        NL_RECV_WINDOW_DEFAULT, emit_to_network, &ectx, &give_up);
        ASSERT_FALSE(give_up);

        if (next_to_send >= total && log.count >= total) break;
    }

    ASSERT_EQ(log.count, total);
    /* Nothing permanently lost. */
    ASSERT_EQ(sender.lanes[NL_RELIABLE_ORDERED].send_ring.unacked_count, 0);
    for (int i = 0; i < total; i++) ASSERT_EQ(log.received[i], (uint32_t)i);

    /* The burst really happened, at a genuinely deep flight -- otherwise
     * this test would prove nothing about a full window. */
    printf("    peak in-flight span %u (ack window %d)\n", peak_span, NL_ACK_WINDOW_BITS);
    CHECK_TRUE(peak_span >= NL_ACK_WINDOW_BITS);

    /* Every scripted-burst sequence was actually dropped once. */
    for (uint32_t i = 0; i < burst_len; i++) ASSERT_EQ(net.burst_drops[i], 1u);

    nl_channel_free(&sender);
    nl_channel_free(&receiver);
}

TEST(test_network_sim_different_seed_reproducible) {
    /* Same seed, same conditions, twice -- must give identical results
     * (deterministic PRNG), which is what makes a failure here
     * reproducible/debuggable rather than a one-off flake. */
    rng_seed(7);
    uint32_t a = rng_next(), b = rng_next(), c = rng_next();
    rng_seed(7);
    ASSERT_EQ(rng_next(), a);
    ASSERT_EQ(rng_next(), b);
    ASSERT_EQ(rng_next(), c);
}

int main(void) {
    printf("=== network condition simulation tests ===\n");
    RUN_TEST(test_network_sim_moderate_loss_and_reorder);
    RUN_TEST(test_network_sim_heavy_loss);
    RUN_TEST(test_network_sim_heavy_reorder_and_duplication);
    RUN_TEST(test_network_sim_sustained_burst_loss_at_full_window);
    RUN_TEST(test_network_sim_different_seed_reproducible);
    TEST_SUMMARY();
}
