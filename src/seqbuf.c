#include "seqbuf.h"
#include <stdlib.h>
#include <string.h>

/* ==================== send ring ==================== */

int nl_send_ring_init(nl_send_ring_t *ring) {
    ring->slots = (nl_send_slot_t *)calloc(NL_SEQ_RING_SIZE, sizeof(nl_send_slot_t));
    if (!ring->slots) return -1;
    ring->next_sequence = 0;
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
    slot->sequence = seq;
    slot->valid = true;
    slot->acked = false;
    slot->len = len;
    slot->send_time_ms = now_ms;
    slot->retry_count = 0;
    memcpy(slot->data, data, len);
    ring->next_sequence = (uint16_t)(seq + 1);
    if (out_seq) *out_seq = seq;
    return true;
}

static void ack_one(nl_send_ring_t *ring, uint16_t seq) {
    nl_send_slot_t *slot = &ring->slots[seq & NL_SEQ_RING_MASK];
    if (slot->valid && slot->sequence == seq) {
        slot->acked = true;
    }
}

void nl_send_ring_ack(nl_send_ring_t *ring, uint16_t ack, uint32_t ack_bits) {
    ack_one(ring, ack);
    for (int i = 0; i < 32; i++) {
        if (ack_bits & (1u << i)) {
            uint16_t seq = (uint16_t)(ack - (i + 1));
            ack_one(ring, seq);
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
