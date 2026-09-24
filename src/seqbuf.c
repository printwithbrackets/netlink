#include "seqbuf.h"
#include <stdlib.h>
#include <string.h>

/* ==================== send ring ==================== */

int nl_send_ring_init(nl_send_ring_t *ring) {
    ring->slots = (nl_send_slot_t *)calloc(NL_SEQ_RING_SIZE, sizeof(nl_send_slot_t));
    if (!ring->slots) return -1;
    ring->next_sequence = 0;
    ring->unacked_count = 0;
    return 0;
}

void nl_send_ring_free(nl_send_ring_t *ring) {
    free(ring->slots);
    ring->slots = NULL;
}

bool nl_send_ring_insert(nl_send_ring_t *ring, const uint8_t *data, uint16_t len,
                          uint64_t now_ms, uint16_t *out_seq) {
    if (len > NL_MAX_PACKET_SIZE_INTERNAL) return false;
    uint16_t seq = ring->next_sequence;
    nl_send_slot_t *slot = &ring->slots[seq & NL_SEQ_RING_MASK];
    /* A slot re-entered after a 65536-sequence wrap must not leave a
     * stale unacked_count bump from the previous life of this index. */
    if (slot->valid && !slot->acked && slot->sequence == seq &&
        ring->unacked_count > 0) {
        ring->unacked_count--;
    }
    slot->sequence = seq;
    slot->valid = true;
    slot->acked = false;
    slot->len = len;
    slot->send_time_ms = now_ms;
    slot->retry_count = 0;
    memcpy(slot->data, data, len);
    ring->unacked_count++;
    ring->next_sequence = (uint16_t)(seq + 1);
    if (out_seq) *out_seq = seq;
    return true;
}

static bool ack_one(nl_send_ring_t *ring, uint16_t seq) {
    nl_send_slot_t *slot = &ring->slots[seq & NL_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == seq && !slot->acked) {
        slot->acked = true;
        if (ring->unacked_count > 0) ring->unacked_count--;
        return true;
    }
    return false;
}

void nl_send_ring_ack(nl_send_ring_t *ring, uint16_t ack, uint32_t ack_bits, uint64_t now_ms,
                       bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms,
                       uint32_t *out_newly_acked) {
    *out_has_rtt_sample = false;
    uint32_t newly = 0;

    nl_send_slot_t *ack_slot = &ring->slots[ack & NL_SEQ_RING_MASK];
    if (ack_slot->valid && ack_slot->sequence == ack && !ack_slot->acked && ack_slot->retry_count == 0) {
        /* Newest sequence, never retransmitted: a clean RTT sample (Karn's
         * algorithm -- see the header comment for why retransmitted or
         * older-via-bitfield sequences are never used as samples). */
        uint64_t elapsed = now_ms - ack_slot->send_time_ms;
        *out_has_rtt_sample = true;
        *out_rtt_sample_ms = (uint32_t)elapsed;
    }

    if (ack_one(ring, ack)) newly++;
    for (int i = 0; i < 32; i++) {
        if (ack_bits & (1u << i)) {
            uint16_t seq = (uint16_t)(ack - (i + 1));
            if (ack_one(ring, seq)) newly++;
        }
    }
    if (out_newly_acked) *out_newly_acked = newly;
}

void nl_send_ring_fast_retransmit(nl_send_ring_t *ring, uint16_t ack, uint32_t ack_bits,
                                   uint32_t reorder_threshold, uint64_t now_ms,
                                   nl_fast_retransmit_fn emit, void *ctx) {
    for (int i = 0; i < NL_SEQ_RING_SIZE; i++) {
        nl_send_slot_t *slot = &ring->slots[i];
        /* slot->acked reflects everything ever acked, including via a
         * prior ack_bits window that has since scrolled past what the
         * current `ack_bits` snapshot can represent. */
        if (!slot->valid || slot->acked) continue;
        if (nl_seq_greater_than(slot->sequence, ack)) continue; /* newer than the ack horizon, not yet due */

        uint16_t age = (uint16_t)(ack - slot->sequence);
        if (age == 0 || age > 32) continue; /* == 0 shouldn't occur unacked; > 32 is outside this ack_bits' window */

        /* Is this slot itself acked per the CURRENT snapshot? Re-derive
         * directly from (ack, ack_bits) rather than only trusting
         * slot->acked, so this function gives correct results even if a
         * caller invokes it without first calling nl_send_ring_ack with
         * these same values (real usage always does both together, but
         * this way correctness doesn't silently depend on that ordering). */
        if (ack_bits & (1u << (age - 1))) continue;

        uint32_t newer_acked = 1; /* `ack` itself is always acked by definition */
        for (uint16_t b = 0; b < (uint16_t)(age - 1); b++) {
            if (ack_bits & (1u << b)) newer_acked++;
        }

        if (newer_acked >= reorder_threshold) {
            emit(ctx, slot->sequence);
            slot->send_time_ms = now_ms; /* same bookkeeping a normal retransmit performs */
            slot->retry_count++;
        }
    }
}

nl_send_slot_t *nl_send_ring_get(nl_send_ring_t *ring, uint16_t sequence) {
    nl_send_slot_t *slot = &ring->slots[sequence & NL_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == sequence) return slot;
    return NULL;
}

/* ==================== receive dedupe ==================== */

int nl_recv_dedupe_init(nl_recv_dedupe_t *d) {
    d->slots = (nl_recv_slot_t *)calloc(NL_SEQ_RING_SIZE, sizeof(nl_recv_slot_t));
    if (!d->slots) return -1;
    d->most_recent = 0;
    d->has_received_any = false;
    return 0;
}

void nl_recv_dedupe_free(nl_recv_dedupe_t *d) {
    free(d->slots);
    d->slots = NULL;
}

bool nl_recv_dedupe_insert(nl_recv_dedupe_t *d, uint16_t sequence) {
    if (!d->has_received_any) {
        d->has_received_any = true;
        d->most_recent = sequence;
    } else if (nl_seq_greater_than(sequence, d->most_recent)) {
        /* Advancing the window: clear slots strictly between the old
         * most-recent and the new one so they don't linger as stale
         * "valid" entries claiming sequences we never actually saw. We
         * only need to clear the ones that would otherwise be
         * misinterpreted -- bounded by the ring size. */
        uint16_t gap = (uint16_t)(sequence - d->most_recent);
        uint16_t to_clear = gap > NL_SEQ_RING_SIZE ? NL_SEQ_RING_SIZE : gap;
        for (uint16_t i = 1; i < to_clear; i++) {
            uint16_t s = (uint16_t)(d->most_recent + i);
            nl_recv_slot_t *slot = &d->slots[s & NL_SEQ_RING_MASK];
            if (slot->sequence != s) slot->valid = false;
        }
        d->most_recent = sequence;
    } else {
        /* sequence <= most_recent (older or equal): reject if it's fallen
         * out of the trackable window. */
        uint16_t age = (uint16_t)(d->most_recent - sequence);
        if (age >= NL_SEQ_RING_SIZE) return false;
    }

    nl_recv_slot_t *slot = &d->slots[sequence & NL_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == sequence) {
        return false; /* duplicate */
    }
    slot->valid = true;
    slot->sequence = sequence;
    return true;
}

void nl_recv_dedupe_build_ack(const nl_recv_dedupe_t *d, uint16_t *out_ack, uint32_t *out_ack_bits) {
    *out_ack = d->most_recent;
    uint32_t bits = 0;
    if (d->has_received_any) {
        for (int i = 0; i < 32; i++) {
            uint16_t s = (uint16_t)(d->most_recent - (i + 1));
            nl_recv_slot_t *slot = &d->slots[s & NL_SEQ_RING_MASK];
            if (slot->valid && slot->sequence == s) {
                bits |= (1u << i);
            }
        }
    }
    *out_ack_bits = bits;
}

/* ==================== reorder ring ==================== */

int nl_reorder_ring_init(nl_reorder_ring_t *ring) {
    ring->slots = (nl_reorder_slot_t *)calloc(NL_SEQ_RING_SIZE, sizeof(nl_reorder_slot_t));
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

void nl_reorder_ring_free(nl_reorder_ring_t *ring) {
    free(ring->slots);
    ring->slots = NULL;
}

bool nl_reorder_ring_insert(nl_reorder_ring_t *ring, uint16_t sequence, const uint8_t *data, uint16_t len) {
    if (len > NL_MAX_PACKET_SIZE_INTERNAL) return false;
    /* Already delivered (older than what we're waiting for)? */
    if (nl_seq_greater_than(ring->next_expected, sequence)) {
        return false; /* stale duplicate */
    }
    uint16_t gap = (uint16_t)(sequence - ring->next_expected);
    if (gap >= NL_SEQ_RING_SIZE) {
        /* Far enough ahead that it doesn't fit the window -- caller's
         * retransmission logic will eventually fill the gap and this
         * will be resent too; drop it rather than corrupt the ring. */
        return false;
    }
    nl_reorder_slot_t *slot = &ring->slots[sequence & NL_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == sequence) {
        return false; /* duplicate already buffered */
    }
    slot->valid = true;
    slot->sequence = sequence;
    slot->len = len;
    memcpy(slot->data, data, len);
    return true;
}

bool nl_reorder_ring_pop_ready(nl_reorder_ring_t *ring, uint8_t *out_data, uint16_t *out_len) {
    if (!ring->initialized) return false;
    nl_reorder_slot_t *slot = &ring->slots[ring->next_expected & NL_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == ring->next_expected) {
        memcpy(out_data, slot->data, slot->len);
        *out_len = slot->len;
        slot->valid = false;
        ring->next_expected = (uint16_t)(ring->next_expected + 1);
        return true;
    }
    return false;
}
