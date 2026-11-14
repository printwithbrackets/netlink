#include "seqbuf.h"
#include <stdlib.h>
#include <string.h>

/* ==================== send ring ==================== */

int wn_send_ring_init(wn_send_ring_t *ring) {
    ring->slots = (wn_send_slot_t *)calloc(WN_SEQ_RING_SIZE, sizeof(wn_send_slot_t));
    if (!ring->slots) return -1;
    ring->next_sequence = 0;
    ring->unacked_count = 0;
    return 0;
}

void wn_send_ring_free(wn_send_ring_t *ring) {
    free(ring->slots);
    ring->slots = NULL;
}

bool wn_send_ring_insert(wn_send_ring_t *ring, const uint8_t *data, uint16_t len,
                          uint64_t now_ms, uint16_t *out_seq) {
    if (len > WN_MAX_PACKET_SIZE_INTERNAL) return false;
    uint16_t seq = ring->next_sequence;
    wn_send_slot_t *slot = &ring->slots[seq & WN_SEQ_RING_MASK];
    /* Refuse to overwrite a live (valid, unacked) slot: that packet has
     * never been acked, so silently replacing it would strand the
     * receiver with a gap it can never fill (the original would never be
     * retransmitted). Callers gate on unacked_count/ring room before
     * inserting; this is the fail-closed backstop if they ever don't.
     * An acked (or stale previous-wrap) slot at this index is safe to
     * recycle -- acked slots don't participate in unacked_count, so the
     * decrement the old overwrite path needed is gone with the refusal. */
    if (slot->valid && !slot->acked) return false;
    slot->sequence = seq;
    slot->valid = true;
    slot->acked = false;
    slot->len = len;
    slot->send_time_ms = now_ms;
    slot->retry_count = 0;
    slot->fast_retx_done = false;
    memcpy(slot->data, data, len);
    ring->unacked_count++;
    ring->next_sequence = (uint16_t)(seq + 1);
    if (out_seq) *out_seq = seq;
    return true;
}

static bool ack_one(wn_send_ring_t *ring, uint16_t seq) {
    wn_send_slot_t *slot = &ring->slots[seq & WN_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == seq && !slot->acked) {
        slot->acked = true;
        /* The slot is retired: whatever cooldown its fast retransmit put
         * on is done with, and the index becomes recyclable. */
        slot->fast_retx_done = false;
        if (ring->unacked_count > 0) ring->unacked_count--;
        return true;
    }
    return false;
}

void wn_send_ring_ack(wn_send_ring_t *ring, uint16_t ack, wn_ack_bits_t ack_bits, uint64_t now_ms,
                       bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms,
                       uint32_t *out_newly_acked) {
    *out_has_rtt_sample = false;
    uint32_t newly = 0;

    wn_send_slot_t *ack_slot = &ring->slots[ack & WN_SEQ_RING_MASK];
    if (ack_slot->valid && ack_slot->sequence == ack && !ack_slot->acked && ack_slot->retry_count == 0) {
        /* Newest sequence, never retransmitted: a clean RTT sample (Karn's
         * algorithm -- see the header comment for why retransmitted or
         * older-via-bitfield sequences are never used as samples). */
        /* Discard the sample if now_ms precedes send_time_ms rather than
         * computing the difference: unsigned subtraction wraps to ~2^64 and
         * the uint32_t truncation lands near 4 billion ms, which would then
         * be reported verbatim by wn_peer_rtt_ms(). now_ms can legitimately
         * appear to go backwards -- it is supplied by the caller, so a
         * cross-CPU timestamp or a wrapped clock source can produce it -- and
         * clamping the result would still poison the estimator. Dropping one
         * bad sample is cheap; a 4-billion-ms srtt is not recoverable. */
        if (now_ms >= ack_slot->send_time_ms) {
            uint64_t elapsed = now_ms - ack_slot->send_time_ms;
            *out_has_rtt_sample = true;
            *out_rtt_sample_ms = (uint32_t)elapsed;
        }
    }

    if (ack_one(ring, ack)) newly++;
    for (int i = 0; i < WN_ACK_WINDOW_BITS; i++) {
        if (ack_bits & ((wn_ack_bits_t)1 << i)) {
            uint16_t seq = (uint16_t)(ack - (i + 1));
            if (ack_one(ring, seq)) newly++;
        }
    }
    if (out_newly_acked) *out_newly_acked = newly;
}

void wn_send_ring_fast_retransmit(wn_send_ring_t *ring, uint16_t ack, wn_ack_bits_t ack_bits,
                                   uint32_t reorder_threshold, uint64_t now_ms,
                                   wn_fast_retransmit_fn emit, void *ctx) {
    for (int i = 0; i < WN_SEQ_RING_SIZE; i++) {
        wn_send_slot_t *slot = &ring->slots[i];
        /* slot->acked reflects everything ever acked, including via a
         * prior ack_bits window that has since scrolled past what the
         * current `ack_bits` snapshot can represent. */
        if (!slot->valid || slot->acked) continue;
        if (wn_seq_greater_than(slot->sequence, ack)) continue; /* newer than the ack horizon, not yet due */

        uint16_t age = (uint16_t)(ack - slot->sequence);
        if (age == 0 || age > WN_ACK_WINDOW_BITS) continue; /* == 0 shouldn't occur unacked; beyond the bitmap's reach */

        /* Is this slot itself acked per the CURRENT snapshot? Re-derive
         * directly from (ack, ack_bits) rather than only trusting
         * slot->acked, so this function gives correct results even if a
         * caller invokes it without first calling wn_send_ring_ack with
         * these same values (real usage always does both together, but
         * this way correctness doesn't silently depend on that ordering). */
        if (ack_bits & ((wn_ack_bits_t)1 << (age - 1))) continue;

        uint32_t newer_acked = 1; /* `ack` itself is always acked by definition */
        for (uint16_t b = 0; b < (uint16_t)(age - 1); b++) {
            if (ack_bits & ((wn_ack_bits_t)1 << b)) newer_acked++;
        }

        if (newer_acked >= reorder_threshold && !slot->fast_retx_done) {
            emit(ctx, slot->sequence);
            /* Refresh the RTO clock so the RTO scan doesn't also fire for
             * this slot on the next tick. Deliberately does NOT touch
             * retry_count: that counter is the give-up budget
             * (WN_MAX_RETRIES), and fast retransmit exists precisely to
             * recover loss the RTO timer would otherwise handle, so
             * charging it here meant ~18 acks within a second could
             * destroy an otherwise healthy connection. */
            slot->send_time_ms = now_ms;
            slot->fast_retx_done = true;
        }
    }
}

wn_send_slot_t *wn_send_ring_get(wn_send_ring_t *ring, uint16_t sequence) {
    wn_send_slot_t *slot = &ring->slots[sequence & WN_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == sequence) return slot;
    return NULL;
}

uint16_t wn_send_ring_oldest_unacked(const wn_send_ring_t *ring) {
    /* Ring indices are sequence & MASK, so slot order is sequence order
     * within the tracked window; comparing with wn_seq_greater_than keeps
     * that correct across a 16-bit wrap. */
    bool found = false;
    uint16_t oldest = 0;
    for (int i = 0; i < WN_SEQ_RING_SIZE; i++) {
        const wn_send_slot_t *slot = &ring->slots[i];
        if (!slot->valid || slot->acked) continue;
        if (!found || wn_seq_greater_than(oldest, slot->sequence)) {
            oldest = slot->sequence;
            found = true;
        }
    }
    return found ? oldest : ring->next_sequence;
}

/* ==================== receive dedupe ==================== */

int wn_recv_dedupe_init(wn_recv_dedupe_t *d) {
    d->slots = (wn_recv_slot_t *)calloc(WN_SEQ_RING_SIZE, sizeof(wn_recv_slot_t));
    if (!d->slots) return -1;
    d->most_recent = 0;
    d->has_received_any = false;
    return 0;
}

void wn_recv_dedupe_free(wn_recv_dedupe_t *d) {
    free(d->slots);
    d->slots = NULL;
}

bool wn_recv_dedupe_insert(wn_recv_dedupe_t *d, uint16_t sequence) {
    if (!d->has_received_any) {
        d->has_received_any = true;
        d->most_recent = sequence;
    } else if (wn_seq_greater_than(sequence, d->most_recent)) {
        /* Advancing the window: clear slots strictly between the old
         * most-recent and the new one so they don't linger as stale
         * "valid" entries claiming sequences we never actually saw. We
         * only need to clear the ones that would otherwise be
         * misinterpreted -- bounded by the ring size. */
        uint16_t gap = (uint16_t)(sequence - d->most_recent);
        uint16_t to_clear = gap > WN_SEQ_RING_SIZE ? WN_SEQ_RING_SIZE : gap;
        for (uint16_t i = 1; i < to_clear; i++) {
            uint16_t s = (uint16_t)(d->most_recent + i);
            wn_recv_slot_t *slot = &d->slots[s & WN_SEQ_RING_MASK];
            if (slot->sequence != s) slot->valid = false;
        }
        d->most_recent = sequence;
    } else {
        /* sequence <= most_recent (older or equal): reject if it's fallen
         * out of the trackable window. */
        uint16_t age = (uint16_t)(d->most_recent - sequence);
        if (age >= WN_SEQ_RING_SIZE) return false;
    }

    wn_recv_slot_t *slot = &d->slots[sequence & WN_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == sequence) {
        return false; /* duplicate */
    }
    slot->valid = true;
    slot->sequence = sequence;
    return true;
}

bool wn_recv_dedupe_seen(const wn_recv_dedupe_t *d, uint16_t sequence) {
    if (!d->has_received_any) return false;
    if (wn_seq_greater_than(sequence, d->most_recent)) return false;
    uint16_t age = (uint16_t)(d->most_recent - sequence);
    if (age >= WN_SEQ_RING_SIZE) return true; /* insert() treats these as duplicates */
    const wn_recv_slot_t *slot = &d->slots[sequence & WN_SEQ_RING_MASK];
    return slot->valid && slot->sequence == sequence;
}

void wn_recv_dedupe_build_ack(const wn_recv_dedupe_t *d, uint16_t *out_ack, wn_ack_bits_t *out_ack_bits) {
    *out_ack = d->most_recent;
    wn_ack_bits_t bits = 0;
    if (d->has_received_any) {
        for (int i = 0; i < WN_ACK_WINDOW_BITS; i++) {
            uint16_t s = (uint16_t)(d->most_recent - (i + 1));
            wn_recv_slot_t *slot = &d->slots[s & WN_SEQ_RING_MASK];
            if (slot->valid && slot->sequence == s) {
                bits |= ((wn_ack_bits_t)1 << i);
            }
        }
    }
    *out_ack_bits = bits;
}

/* ==================== reorder ring ==================== */

int wn_reorder_ring_init(wn_reorder_ring_t *ring) {
    ring->slots = (wn_reorder_slot_t *)calloc(WN_SEQ_RING_SIZE, sizeof(wn_reorder_slot_t));
    if (!ring->slots) return -1;
    /* Both sides of a connection always start a lane's sequence numbering
     * at 0, so the receiver can know the correct delivery baseline up
     * front -- it must NOT be inferred from whichever packet happens to
     * arrive first. If it were, a reordered first packet (e.g. fragment
     * index 1 of a message arriving before fragment index 0) would be
     * mistaken for "the start", and would be delivered immediately
     * instead of correctly waiting for sequence 0 -- silently violating
     * the in-order guarantee this whole structure exists to provide. */
    ring->next_expected = 0;
    ring->initialized = true;
    return 0;
}

void wn_reorder_ring_free(wn_reorder_ring_t *ring) {
    free(ring->slots);
    ring->slots = NULL;
}

bool wn_reorder_ring_reachable(const wn_reorder_ring_t *ring, uint16_t sequence) {
    if (wn_seq_greater_than(ring->next_expected, sequence)) return true; /* stale */
    uint16_t gap = (uint16_t)(sequence - ring->next_expected);
    return gap < WN_SEQ_RING_SIZE;
}

bool wn_reorder_ring_insert(wn_reorder_ring_t *ring, uint16_t sequence, const uint8_t *data, uint16_t len) {
    if (len > WN_MAX_PACKET_SIZE_INTERNAL) return false;
    /* Already delivered (older than what we're waiting for)? */
    if (wn_seq_greater_than(ring->next_expected, sequence)) {
        return false; /* stale duplicate */
    }
    uint16_t gap = (uint16_t)(sequence - ring->next_expected);
    if (gap >= WN_SEQ_RING_SIZE) {
        /* Far enough ahead that it doesn't fit the window -- caller's
         * retransmission logic will eventually fill the gap and this
         * will be resent too; drop it rather than corrupt the ring. */
        return false;
    }
    wn_reorder_slot_t *slot = &ring->slots[sequence & WN_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == sequence) {
        return false; /* duplicate already buffered */
    }
    slot->valid = true;
    slot->sequence = sequence;
    slot->len = len;
    memcpy(slot->data, data, len);
    return true;
}

bool wn_reorder_ring_pop_ready(wn_reorder_ring_t *ring, uint8_t *out_data, uint16_t *out_len) {
    if (!ring->initialized) return false;
    wn_reorder_slot_t *slot = &ring->slots[ring->next_expected & WN_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == ring->next_expected) {
        memcpy(out_data, slot->data, slot->len);
        *out_len = slot->len;
        slot->valid = false;
        ring->next_expected = (uint16_t)(ring->next_expected + 1);
        return true;
    }
    return false;
}
