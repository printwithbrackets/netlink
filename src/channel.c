#include "channel.h"
#include "byteorder.h"
#include <string.h>

void nl_channel_init(nl_channel_t *chan) {
    memset(chan, 0, sizeof(*chan));
}

void nl_channel_free(nl_channel_t *chan) {
    for (int i = 0; i < NL_LANES_PER_CHANNEL; i++) {
        nl_lane_t *lane = &chan->lanes[i];
        if (lane->send_ring_init) nl_send_ring_free(&lane->send_ring);
        if (lane->recv_dedupe_init) nl_recv_dedupe_free(&lane->recv_dedupe);
        if (lane->reorder_ring_init) nl_reorder_ring_free(&lane->reorder_ring);
        if (lane->reassembly_init) nl_reassembly_tracker_free(&lane->reassembly);
    }
    memset(chan, 0, sizeof(*chan));
}

static bool is_reliable(nl_delivery_t d) {
    return d == NL_RELIABLE_UNORDERED || d == NL_RELIABLE_ORDERED;
}

nl_result_t nl_channel_send(nl_channel_t *chan, uint64_t now_ms, uint8_t channel_id, nl_delivery_t delivery,
                             const uint8_t *data, size_t len,
                             nl_channel_emit_fn emit, void *ctx) {
    if ((int)delivery < 0 || (int)delivery >= NL_LANES_PER_CHANNEL) return NL_ERR_INVALID_ARGUMENT;
    if (len > 0 && !data) return NL_ERR_INVALID_ARGUMENT;
    if (len > NL_MAX_MESSAGE_SIZE) return NL_ERR_MESSAGE_TOO_LARGE;

    nl_lane_t *lane = &chan->lanes[delivery];
    lane->delivery = delivery;
    lane->in_use = true;
    bool reliable = is_reliable(delivery);
    if (reliable && !lane->send_ring_init) {
        if (nl_send_ring_init(&lane->send_ring) != 0) return NL_ERR_OUT_OF_MEMORY;
        lane->send_ring_init = true;
    }

    uint16_t frag_count = 1;
    if (len > NL_FRAGMENT_CHUNK_SIZE) {
        frag_count = nl_fragment_count_needed(len);
        if (frag_count == 0) return NL_ERR_MESSAGE_TOO_LARGE;
    }
    bool is_fragmented = frag_count > 1;
    uint16_t message_id = is_fragmented ? lane->next_message_id++ : 0;

    for (uint16_t i = 0; i < frag_count; i++) {
        const uint8_t *chunk_ptr;
        uint16_t chunk_len;
        if (is_fragmented) {
            nl_fragment_get_chunk(data, len, i, &chunk_ptr, &chunk_len);
        } else {
            chunk_ptr = data;
            chunk_len = (uint16_t)len;
        }

        /* "lane payload": is_fragment marker onward -- what gets stored
         * for retransmission/reordering, independent of the common header
         * fields that get refreshed on every send/retransmit. */
        uint8_t lane_payload[NL_MAX_PACKET_SIZE];
        size_t lp_len = 0;
        lane_payload[lp_len++] = is_fragmented ? 1 : 0;
        if (is_fragmented) {
            nl_put_u16(lane_payload + lp_len, message_id); lp_len += 2;
            nl_put_u16(lane_payload + lp_len, i); lp_len += 2;
            nl_put_u16(lane_payload + lp_len, frag_count); lp_len += 2;
        }
        memcpy(lane_payload + lp_len, chunk_ptr, chunk_len);
        lp_len += chunk_len;

        uint16_t seq;
        if (reliable) {
            if (!nl_send_ring_insert(&lane->send_ring, lane_payload, (uint16_t)lp_len, now_ms, &seq)) {
                return NL_ERR_INTERNAL; /* unreachable: lp_len is always within NL_MAX_PACKET_SIZE */
            }
        } else {
            seq = lane->next_sequence++;
        }

        uint16_t ack = 0;
        uint32_t ack_bits = 0;
        if (reliable && lane->recv_dedupe_init) {
            nl_recv_dedupe_build_ack(&lane->recv_dedupe, &ack, &ack_bits);
        }

        uint8_t wire[NL_MAX_PACKET_SIZE];
        size_t off = 0;
        wire[off++] = channel_id;
        wire[off++] = (uint8_t)delivery;
        nl_put_u16(wire + off, seq); off += 2;
        nl_put_u16(wire + off, ack); off += 2;
        nl_put_u32(wire + off, ack_bits); off += 4;
        memcpy(wire + off, lane_payload, lp_len);
        off += lp_len;

        emit(ctx, wire, (uint16_t)off);
    }

    return NL_OK;
}

static void deliver_or_reassemble(nl_lane_t *lane, uint64_t now_ms, uint8_t channel_id, nl_delivery_t delivery,
                                   bool is_fragment, uint16_t message_id, uint16_t frag_index, uint16_t frag_count,
                                   const uint8_t *chunk, uint16_t chunk_len,
                                   nl_channel_deliver_fn deliver, void *ctx) {
    if (!is_fragment) {
        deliver(ctx, channel_id, delivery, chunk, chunk_len);
        return;
    }
    if (!lane->reassembly_init) {
        nl_reassembly_tracker_init(&lane->reassembly);
        lane->reassembly_init = true;
    }
    const uint8_t *out_data;
    uint32_t out_len;
    nl_reassemble_result_t r = nl_reassembly_feed(&lane->reassembly, now_ms, message_id, frag_index,
                                                   frag_count, chunk, chunk_len, &out_data, &out_len);
    if (r == NL_REASSEMBLE_COMPLETE) {
        deliver(ctx, channel_id, delivery, out_data, out_len);
    }
    /* PENDING or INVALID: nothing deliverable yet (or a malformed fragment
     * was silently dropped -- fragment.c already validated the wire
     * fields defensively). */
}

static void emit_wire_for_slot(nl_lane_t *lane, uint8_t channel_id, uint8_t delivery,
                                nl_send_slot_t *slot, nl_channel_retransmit_fn retransmit, void *ctx) {
    uint16_t ack = 0;
    uint32_t ack_bits = 0;
    if (lane->recv_dedupe_init) nl_recv_dedupe_build_ack(&lane->recv_dedupe, &ack, &ack_bits);

    uint8_t wire[NL_MAX_PACKET_SIZE];
    size_t off = 0;
    wire[off++] = channel_id;
    wire[off++] = delivery;
    nl_put_u16(wire + off, slot->sequence); off += 2;
    nl_put_u16(wire + off, ack); off += 2;
    nl_put_u32(wire + off, ack_bits); off += 4;
    memcpy(wire + off, slot->data, slot->len);
    off += slot->len;

    retransmit(ctx, wire, (uint16_t)off);
}

typedef struct {
    nl_lane_t *lane;
    uint8_t channel_id;
    uint8_t delivery;
    nl_channel_retransmit_fn retransmit;
    void *retransmit_ctx;
} fast_retransmit_bridge_t;

static void fast_retransmit_bridge(void *ctx, uint16_t sequence) {
    fast_retransmit_bridge_t *b = (fast_retransmit_bridge_t *)ctx;
    nl_send_slot_t *slot = nl_send_ring_get(&b->lane->send_ring, sequence);
    if (!slot) return; /* shouldn't happen: fast_retransmit only reports slots it found itself */
    emit_wire_for_slot(b->lane, b->channel_id, b->delivery, slot, b->retransmit, b->retransmit_ctx);
}

void nl_channel_on_receive(nl_channel_t *chan, uint64_t now_ms,
                            const uint8_t *wire_payload, uint16_t wire_len,
                            nl_channel_deliver_fn deliver, void *deliver_ctx,
                            nl_channel_retransmit_fn retransmit, void *retransmit_ctx,
                            bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms) {
    if (out_has_rtt_sample) *out_has_rtt_sample = false;
    if (wire_len < NL_DATA_HEADER_SIZE) return; /* malformed, drop */

    size_t off = 0;
    uint8_t channel_id = wire_payload[off++];
    uint8_t delivery_raw = wire_payload[off++];
    if (delivery_raw >= NL_LANES_PER_CHANNEL) return;
    nl_delivery_t delivery = (nl_delivery_t)delivery_raw;
    uint16_t seq = nl_get_u16(wire_payload + off); off += 2;
    uint16_t ack = nl_get_u16(wire_payload + off); off += 2;
    uint32_t ack_bits = nl_get_u32(wire_payload + off); off += 4;
    uint8_t is_fragment = wire_payload[off++];
    if (is_fragment > 1) return;

    nl_lane_t *lane = &chan->lanes[delivery];
    lane->delivery = delivery;
    lane->in_use = true;
    bool reliable = is_reliable(delivery);

    if (reliable) {
        if (!lane->send_ring_init) {
            if (nl_send_ring_init(&lane->send_ring) != 0) return;
            lane->send_ring_init = true;
        }
        bool has_sample = false;
        uint32_t sample_ms = 0;
        nl_send_ring_ack(&lane->send_ring, ack, ack_bits, now_ms, &has_sample, &sample_ms);
        if (has_sample && out_has_rtt_sample) {
            *out_has_rtt_sample = true;
            *out_rtt_sample_ms = sample_ms;
        }

        if (retransmit) {
            fast_retransmit_bridge_t bridge = { lane, channel_id, (uint8_t)delivery, retransmit, retransmit_ctx };
            nl_send_ring_fast_retransmit(&lane->send_ring, ack, ack_bits, NL_FAST_RETRANSMIT_THRESHOLD,
                                          now_ms, fast_retransmit_bridge, &bridge);
        }
    }

    uint16_t message_id = 0, frag_index = 0, frag_count = 1;
    if (is_fragment) {
        if ((size_t)wire_len < off + NL_FRAGMENT_HEADER_SIZE) return; /* malformed */
        message_id = nl_get_u16(wire_payload + off); off += 2;
        frag_index = nl_get_u16(wire_payload + off); off += 2;
        frag_count = nl_get_u16(wire_payload + off); off += 2;
    }
    const uint8_t *chunk = wire_payload + off;
    uint16_t chunk_len = (uint16_t)(wire_len - off);

    if (delivery == NL_UNRELIABLE) {
        deliver_or_reassemble(lane, now_ms, channel_id, delivery, is_fragment, message_id,
                               frag_index, frag_count, chunk, chunk_len, deliver, deliver_ctx);
        return;
    }

    if (delivery == NL_UNRELIABLE_SEQUENCED) {
        if (!is_fragment) {
            if (lane->seq_has_received_any && !nl_seq_greater_than(seq, lane->seq_highest_seen)) {
                return; /* stale/out-of-order for a sequenced lane: drop, no retry */
            }
            lane->seq_highest_seen = seq;
            lane->seq_has_received_any = true;
            deliver(deliver_ctx, channel_id, delivery, chunk, chunk_len);
            return;
        }
        /* Fragmented sequenced message: every fragment must reach reassembly
         * even if individual sequence numbers arrive out of order -- gating
         * each fragment on seq_highest_seen would drop the earlier fragment
         * of a reordered pair and strand the message incomplete forever.
         * Track this message's highest fragment seq instead, and apply the
         * stale-drop gate only when the whole message is ready to deliver. */
        if (!lane->seq_frag_active || lane->seq_frag_msg_id != message_id) {
            lane->seq_frag_active = true;
            lane->seq_frag_msg_id = message_id;
            lane->seq_frag_max_seq = seq;
        } else if (nl_seq_greater_than(seq, lane->seq_frag_max_seq)) {
            lane->seq_frag_max_seq = seq;
        }
        if (!lane->reassembly_init) {
            nl_reassembly_tracker_init(&lane->reassembly);
            lane->reassembly_init = true;
        }
        const uint8_t *out_data;
        uint32_t out_len;
        nl_reassemble_result_t r = nl_reassembly_feed(&lane->reassembly, now_ms, message_id, frag_index,
                                                       frag_count, chunk, chunk_len, &out_data, &out_len);
        if (r == NL_REASSEMBLE_COMPLETE) {
            lane->seq_frag_active = false;
            if (!lane->seq_has_received_any ||
                nl_seq_greater_than(lane->seq_frag_max_seq, lane->seq_highest_seen)) {
                lane->seq_highest_seen = lane->seq_frag_max_seq;
                lane->seq_has_received_any = true;
                deliver(deliver_ctx, channel_id, delivery, out_data, out_len);
            }
            /* else: whole message is stale relative to already-delivered data */
        }
        return;
    }

    /* Reliable modes: dedupe first. */
    if (!lane->recv_dedupe_init) {
        if (nl_recv_dedupe_init(&lane->recv_dedupe) != 0) return;
        lane->recv_dedupe_init = true;
    }
    if (!nl_recv_dedupe_insert(&lane->recv_dedupe, seq)) return; /* duplicate */

    if (delivery == NL_RELIABLE_UNORDERED) {
        deliver_or_reassemble(lane, now_ms, channel_id, delivery, is_fragment, message_id,
                               frag_index, frag_count, chunk, chunk_len, deliver, deliver_ctx);
        return;
    }

    /* NL_RELIABLE_ORDERED: buffer in the reorder ring, keyed by `seq`,
     * storing everything from the is_fragment marker onward so it can be
     * re-parsed once released in order. */
    if (!lane->reorder_ring_init) {
        if (nl_reorder_ring_init(&lane->reorder_ring) != 0) return;
        lane->reorder_ring_init = true;
    }
    const uint8_t *reorder_payload = wire_payload + (NL_DATA_HEADER_SIZE - 1); /* is_fragment onward */
    uint16_t reorder_len = (uint16_t)(wire_len - (NL_DATA_HEADER_SIZE - 1));
    nl_reorder_ring_insert(&lane->reorder_ring, seq, reorder_payload, reorder_len);

    uint8_t pop_buf[NL_MAX_PACKET_SIZE];
    uint16_t pop_len;
    while (nl_reorder_ring_pop_ready(&lane->reorder_ring, pop_buf, &pop_len)) {
        size_t p = 0;
        uint8_t pf = pop_buf[p++];
        uint16_t p_mid = 0, p_idx = 0, p_cnt = 1;
        if (pf) {
            if (pop_len < p + NL_FRAGMENT_HEADER_SIZE) continue; /* corrupt buffered entry, skip */
            p_mid = nl_get_u16(pop_buf + p); p += 2;
            p_idx = nl_get_u16(pop_buf + p); p += 2;
            p_cnt = nl_get_u16(pop_buf + p); p += 2;
        }
        deliver_or_reassemble(lane, now_ms, channel_id, delivery, pf, p_mid, p_idx, p_cnt,
                               pop_buf + p, (uint16_t)(pop_len - p), deliver, deliver_ctx);
    }
}

void nl_channel_tick(nl_channel_t *chan, uint8_t channel_id, uint64_t now_ms, uint32_t rto_ms,
                      uint32_t max_retries, nl_channel_retransmit_fn retransmit, void *ctx,
                      bool *out_give_up) {
    *out_give_up = false;
    /* Reclaim stale reassembly slots every tick (fragment.h documents this
     * as the expected caller); without it, incomplete messages only free
     * their slots under eviction pressure and the timeout never fires. */
    for (int i = 0; i < NL_LANES_PER_CHANNEL; i++) {
        if (chan->lanes[i].reassembly_init) {
            nl_reassembly_expire(&chan->lanes[i].reassembly, now_ms);
        }
    }
    for (int d = NL_RELIABLE_UNORDERED; d <= NL_RELIABLE_ORDERED; d++) {
        nl_lane_t *lane = &chan->lanes[d];
        if (!lane->in_use || !lane->send_ring_init) continue;
        nl_send_ring_t *ring = &lane->send_ring;

        for (int i = 0; i < NL_SEQ_RING_SIZE; i++) {
            nl_send_slot_t *slot = &ring->slots[i];
            if (!slot->valid || slot->acked) continue;
            if (now_ms - slot->send_time_ms < rto_ms) continue;

            if (slot->retry_count >= max_retries) {
                *out_give_up = true;
                continue;
            }

            emit_wire_for_slot(lane, channel_id, (uint8_t)d, slot, retransmit, ctx);

            /* Reset the retransmit clock -- without this the same slot
             * would look "due" again on the very next tick and we'd fire
             * a retransmission storm instead of waiting another RTO. */
            slot->send_time_ms = now_ms;
            slot->retry_count++;
        }
    }
}
