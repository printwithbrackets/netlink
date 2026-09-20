#include "fragment.h"
#include <stdlib.h>
#include <string.h>

uint16_t nl_fragment_count_needed(size_t message_len) {
    if (message_len == 0 || message_len > NL_MAX_MESSAGE_SIZE) return 0;
    size_t count = (message_len + NL_FRAGMENT_CHUNK_SIZE - 1) / NL_FRAGMENT_CHUNK_SIZE;
    if (count > NL_MAX_FRAGMENTS) return 0;
    return (uint16_t)count;
}

void nl_fragment_get_chunk(const uint8_t *data, size_t total_len, uint16_t index,
                            const uint8_t **out_ptr, uint16_t *out_len) {
    size_t offset = (size_t)index * NL_FRAGMENT_CHUNK_SIZE;
    size_t remaining = total_len - offset;
    size_t len = remaining < NL_FRAGMENT_CHUNK_SIZE ? remaining : NL_FRAGMENT_CHUNK_SIZE;
    *out_ptr = data + offset;
    *out_len = (uint16_t)len;
}

void nl_reassembly_tracker_init(nl_reassembly_tracker_t *t) {
    memset(t, 0, sizeof(*t));
}

static void slot_release(nl_reassembly_slot_t *slot) {
    free(slot->fragment_received);
    free(slot->data);
    memset(slot, 0, sizeof(*slot));
}

void nl_reassembly_tracker_free(nl_reassembly_tracker_t *t) {
    for (int i = 0; i < NL_REASSEMBLY_SLOTS; i++) {
        slot_release(&t->slots[i]);
    }
}

static nl_reassembly_slot_t *find_active(nl_reassembly_tracker_t *t, uint16_t message_id) {
    for (int i = 0; i < NL_REASSEMBLY_SLOTS; i++) {
        if (t->slots[i].active && t->slots[i].message_id == message_id) return &t->slots[i];
    }
    return NULL;
}

static nl_reassembly_slot_t *acquire_slot(nl_reassembly_tracker_t *t) {
    /* Prefer a never-used or already-inactive slot. */
    for (int i = 0; i < NL_REASSEMBLY_SLOTS; i++) {
        if (!t->slots[i].active) return &t->slots[i];
    }
    /* All slots busy with distinct in-flight messages: evict the oldest
     * rather than letting an attacker (or an unlucky burst of legitimate
     * traffic) grow memory without bound. */
    int oldest = 0;
    for (int i = 1; i < NL_REASSEMBLY_SLOTS; i++) {
        if (t->slots[i].first_seen_ms < t->slots[oldest].first_seen_ms) oldest = i;
    }
    return &t->slots[oldest];
}

nl_reassemble_result_t nl_reassembly_feed(nl_reassembly_tracker_t *t, uint64_t now_ms,
                                           uint16_t message_id, uint16_t fragment_index,
                                           uint16_t fragment_count,
                                           const uint8_t *chunk, uint16_t chunk_len,
                                           const uint8_t **out_data, uint32_t *out_len) {
    /* ---- validate attacker-controlled fields before touching memory ---- */
    if (fragment_count == 0 || fragment_count > NL_MAX_FRAGMENTS) return NL_REASSEMBLE_INVALID;
    if (fragment_index >= fragment_count) return NL_REASSEMBLE_INVALID;
    if (chunk_len > NL_FRAGMENT_CHUNK_SIZE) return NL_REASSEMBLE_INVALID;
    if ((size_t)fragment_count * NL_FRAGMENT_CHUNK_SIZE > NL_MAX_MESSAGE_SIZE) return NL_REASSEMBLE_INVALID;
    bool is_last = (fragment_index == (uint16_t)(fragment_count - 1));
    if (!is_last && chunk_len != NL_FRAGMENT_CHUNK_SIZE) return NL_REASSEMBLE_INVALID;
    if (chunk_len == 0 && fragment_count > 1 && is_last) {
        /* A zero-length final fragment is only sensible when the message
         * length is an exact multiple of the chunk size AND fragment_count
         * already accounts for it -- nl_fragment_count_needed() never
         * produces a trailing empty fragment, so this shape is invalid. */
        return NL_REASSEMBLE_INVALID;
    }

    nl_reassembly_slot_t *slot = find_active(t, message_id);
    if (slot) {
        if (slot->fragment_count != fragment_count) {
            /* Inconsistent claim about an in-flight message_id -- reject
             * the new packet, leave the existing reassembly untouched. */
            return NL_REASSEMBLE_INVALID;
        }
    } else {
        slot = acquire_slot(t);
        if (slot->active) slot_release(slot); /* evicting an in-progress one */

        free(slot->fragment_received);
        slot->fragment_received = (bool *)calloc(fragment_count, sizeof(bool));
        if (!slot->fragment_received) return NL_REASSEMBLE_INVALID;

        if (!slot->data) {
            slot->data = (uint8_t *)malloc(NL_MAX_MESSAGE_SIZE);
            if (!slot->data) { free(slot->fragment_received); slot->fragment_received = NULL; return NL_REASSEMBLE_INVALID; }
        }

        slot->active = true;
        slot->message_id = message_id;
        slot->fragment_count = fragment_count;
        slot->received_count = 0;
        slot->total_len_known = false;
        slot->total_len = 0;
        slot->first_seen_ms = now_ms;
    }

    if (slot->fragment_received[fragment_index]) {
        return NL_REASSEMBLE_PENDING; /* duplicate fragment, already have it */
    }

    size_t offset = (size_t)fragment_index * NL_FRAGMENT_CHUNK_SIZE;
    if (chunk_len > 0) {
        memcpy(slot->data + offset, chunk, chunk_len);
    }
    slot->fragment_received[fragment_index] = true;
    slot->received_count++;

    if (is_last) {
        slot->total_len = (uint32_t)(offset + chunk_len);
        slot->total_len_known = true;
    }

    if (slot->received_count == slot->fragment_count) {
        if (!slot->total_len_known) {
            /* Should be unreachable: received_count == fragment_count
             * implies the last index was among them. Fail safe anyway
             * rather than deliver a partially-garbage buffer. */
            slot->active = false;
            return NL_REASSEMBLE_INVALID;
        }
        *out_data = slot->data;
        *out_len = slot->total_len;
        slot->active = false; /* buffers kept allocated for reuse */
        return NL_REASSEMBLE_COMPLETE;
    }

    return NL_REASSEMBLE_PENDING;
}

void nl_reassembly_expire(nl_reassembly_tracker_t *t, uint64_t now_ms) {
    for (int i = 0; i < NL_REASSEMBLY_SLOTS; i++) {
        nl_reassembly_slot_t *slot = &t->slots[i];
        if (slot->active && (now_ms - slot->first_seen_ms) > NL_REASSEMBLY_TIMEOUT_MS) {
            slot->active = false;
            /* Buffers intentionally kept allocated for the next reuse. */
        }
    }
}
