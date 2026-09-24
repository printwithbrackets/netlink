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
                             const uint8_t *data, size_t len, uint16_t local_rwnd,
                             nl_channel_emit_fn emit, void *ctx) {
    uint16_t message_id = 0, sent = 0, frag_count = 0;
    nl_result_t r = nl_channel_send_range(chan, now_ms, channel_id, delivery, data, len, local_rwnd,
                                          /*start_frag*/ 0, /*max_frags*/ 0, &message_id,
                                          emit, ctx, &sent, &frag_count);
    /* max_frags 0 = unlimited, so a short count here means the send ring
     * rejected a slot mid-message -- same failure the old monolithic loop
     * returned NL_ERR_INTERNAL for (after emitting the earlier fragments,
     * which this preserves). */
    if (r == NL_OK && sent < frag_count) return NL_ERR_INTERNAL;
    return r;
}

nl_result_t nl_channel_send_range(nl_channel_t *chan, uint64_t now_ms, uint8_t channel_id,
                                  nl_delivery_t delivery, const uint8_t *data, size_t len,
                                  uint16_t local_rwnd, uint16_t start_frag, uint16_t max_frags,
                                  uint16_t *io_message_id, nl_channel_emit_fn emit, void *ctx,
                                  uint16_t *out_sent_frags, uint16_t *out_frag_count) {
    if ((int)delivery < 0 || (int)delivery >= NL_LANES_PER_CHANNEL) return NL_ERR_INVALID_ARGUMENT;
    if (len > 0 && !data) return NL_ERR_INVALID_ARGUMENT;
    if (len > NL_MAX_MESSAGE_SIZE) return NL_ERR_MESSAGE_TOO_LARGE;
    if (out_sent_frags) *out_sent_frags = 0;

    uint16_t frag_count = 1;
    if (len > NL_FRAGMENT_CHUNK_SIZE) {
        frag_count = nl_fragment_count_needed(len);
        if (frag_count == 0) return NL_ERR_MESSAGE_TOO_LARGE;
    }
    if (out_frag_count) *out_frag_count = frag_count;
    if (start_frag >= frag_count) {
        /* Continuation already complete (or bogus start): nothing to do. */
        return NL_OK;
    }

    nl_lane_t *lane = &chan->lanes[delivery];
    lane->delivery = delivery;
    lane->in_use = true;
    bool reliable = is_reliable(delivery);
    if (reliable && !lane->send_ring_init) {
        if (nl_send_ring_init(&lane->send_ring) != 0) return NL_ERR_OUT_OF_MEMORY;
        lane->send_ring_init = true;
    }

    bool is_fragmented = frag_count > 1;
    uint16_t message_id;
    if (is_fragmented && start_frag == 0) {
        message_id = lane->next_message_id++;
    } else if (is_fragmented) {
        message_id = io_message_id ? *io_message_id : 0;
    } else {
        message_id = 0;
    }
    if (io_message_id) *io_message_id = message_id;

    uint16_t end_frag = frag_count;
    if (max_frags != 0 && (uint32_t)start_frag + max_frags < end_frag) {
        end_frag = (uint16_t)(start_frag + max_frags);
    }

    for (uint16_t i = start_frag; i < end_frag; i++) {
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
                /* Ring full of unacked slots: report the partial send.
                 * Connection-level gating normally prevents this; the
                 * refusal path keeps existing live slots intact (a
                 * previously-sent-but-unacked packet must not be lost). */
                if (out_sent_frags) *out_sent_frags = i;
                return NL_OK;
            }
        } else {
            seq = lane->next_sequence++;
        }

        uint16_t ack = 0;
        uint32_t ack_bits = 0;
        if (reliable && lane->recv_dedupe_init) {
            nl_recv_dedupe_build_ack(&lane->recv_dedupe, &ack, &ack_bits);
            lane->ack_dirty = false; /* piggybacked on this DATA */
        }

        uint8_t wire[NL_MAX_PACKET_SIZE];
        size_t off = 0;
        wire[off++] = channel_id;
        wire[off++] = (uint8_t)delivery;
        nl_put_u16(wire + off, seq); off += 2;
        nl_put_u16(wire + off, ack); off += 2;
        nl_put_u32(wire + off, ack_bits); off += 4;
        nl_put_u16(wire + off, local_rwnd); off += 2;
        memcpy(wire + off, lane_payload, lp_len);
        off += lp_len;

        emit(ctx, wire, (uint16_t)off);
    }

    if (out_sent_frags) *out_sent_frags = (uint16_t)(end_frag - start_frag);
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
                                nl_send_slot_t *slot, uint16_t local_rwnd,
                                nl_channel_retransmit_fn retransmit, void *ctx) {
    uint16_t ack = 0;
    uint32_t ack_bits = 0;
    if (lane->recv_dedupe_init) {
        nl_recv_dedupe_build_ack(&lane->recv_dedupe, &ack, &ack_bits);
        lane->ack_dirty = false; /* this retransmit carries a fresh ack */
    }

    uint8_t wire[NL_MAX_PACKET_SIZE];
    size_t off = 0;
    wire[off++] = channel_id;
    wire[off++] = delivery;
    nl_put_u16(wire + off, slot->sequence); off += 2;
    nl_put_u16(wire + off, ack); off += 2;
    nl_put_u32(wire + off, ack_bits); off += 4;
    nl_put_u16(wire + off, local_rwnd); off += 2;
    memcpy(wire + off, slot->data, slot->len);
    off += slot->len;

    retransmit(ctx, wire, (uint16_t)off);
}

typedef struct {
    nl_lane_t *lane;
    uint8_t channel_id;
    uint8_t delivery;
    uint16_t local_rwnd;
    nl_channel_retransmit_fn retransmit;
    void *retransmit_ctx;
} fast_retransmit_bridge_t;

static void fast_retransmit_bridge(void *ctx, uint16_t sequence) {
    fast_retransmit_bridge_t *b = (fast_retransmit_bridge_t *)ctx;
    nl_send_slot_t *slot = nl_send_ring_get(&b->lane->send_ring, sequence);
    if (!slot) return; /* shouldn't happen: fast_retransmit only reports slots it found itself */
    emit_wire_for_slot(b->lane, b->channel_id, b->delivery, slot, b->local_rwnd,
                       b->retransmit, b->retransmit_ctx);
}

void nl_channel_apply_ack(nl_channel_t *chan, uint64_t now_ms, uint8_t channel_id,
                          nl_delivery_t delivery, uint16_t ack, uint32_t ack_bits,
                          uint16_t local_rwnd,
                          nl_channel_retransmit_fn retransmit, void *retransmit_ctx,
                          bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms,
                          uint32_t *out_newly_acked) {
    if (out_has_rtt_sample) *out_has_rtt_sample = false;
    if (out_newly_acked) *out_newly_acked = 0;
    if ((int)delivery < 0 || (int)delivery >= NL_LANES_PER_CHANNEL) return;
    if (!is_reliable(delivery)) return;

    nl_lane_t *lane = &chan->lanes[delivery];
    if (!lane->send_ring_init) {
        if (nl_send_ring_init(&lane->send_ring) != 0) return;
        lane->send_ring_init = true;
    }
    bool has_sample = false;
    uint32_t sample_ms = 0;
    uint32_t newly = 0;
    nl_send_ring_ack(&lane->send_ring, ack, ack_bits, now_ms, &has_sample, &sample_ms, &newly);
    if (out_newly_acked) *out_newly_acked = newly;
    if (has_sample && out_has_rtt_sample) {
        *out_has_rtt_sample = true;
        *out_rtt_sample_ms = sample_ms;
    }

    if (retransmit) {
        fast_retransmit_bridge_t bridge = { lane, channel_id, (uint8_t)delivery, local_rwnd,
                                            retransmit, retransmit_ctx };
        nl_send_ring_fast_retransmit(&lane->send_ring, ack, ack_bits, NL_FAST_RETRANSMIT_THRESHOLD,
                                      now_ms, fast_retransmit_bridge, &bridge);
    }
}

void nl_channel_on_receive(nl_channel_t *chan, uint64_t now_ms,
                            const uint8_t *wire_payload, uint16_t wire_len,
                            uint16_t local_rwnd,
                            nl_channel_deliver_fn deliver, void *deliver_ctx,
                            nl_channel_retransmit_fn retransmit, void *retransmit_ctx,
                            bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms,
                            uint32_t *out_newly_acked, uint16_t *out_rwnd) {
    if (out_has_rtt_sample) *out_has_rtt_sample = false;
    if (out_newly_acked) *out_newly_acked = 0;
    if (wire_len < NL_DATA_HEADER_SIZE) return; /* malformed, drop */

    size_t off = 0;
    uint8_t channel_id = wire_payload[off++];
    uint8_t delivery_raw = wire_payload[off++];
    if (delivery_raw >= NL_LANES_PER_CHANNEL) return;
    nl_delivery_t delivery = (nl_delivery_t)delivery_raw;
    uint16_t seq = nl_get_u16(wire_payload + off); off += 2;
    uint16_t ack = nl_get_u16(wire_payload + off); off += 2;
    uint32_t ack_bits = nl_get_u32(wire_payload + off); off += 4;
    uint16_t peer_rwnd = nl_get_u16(wire_payload + off); off += 2;
    if (out_rwnd) *out_rwnd = peer_rwnd;
    uint8_t is_fragment = wire_payload[off++];
    if (is_fragment > 1) return;

    nl_lane_t *lane = &chan->lanes[delivery];
    lane->delivery = delivery;
    lane->in_use = true;
    bool reliable = is_reliable(delivery);

    if (reliable) {
        nl_channel_apply_ack(chan, now_ms, channel_id, delivery, ack, ack_bits, local_rwnd,
                             retransmit, retransmit_ctx,
                             out_has_rtt_sample, out_rtt_sample_ms, out_newly_acked);
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
    /* Even a duplicate needs an ack: the sender hasn't heard this
     * sequence was received (that's why it retransmitted). Mark dirty
     * before the dup check so the flush isn't skipped. */
    bool is_new_seq = nl_recv_dedupe_insert(&lane->recv_dedupe, seq);
    lane->ack_dirty = true;
    if (!is_new_seq) return; /* duplicate payload: ack state updated, delivery skipped */

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
                      uint32_t max_retries, uint16_t local_rwnd,
                      nl_channel_retransmit_fn retransmit, void *ctx,
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
            /* Exponential backoff: double the base RTO per retry (capped
             * at NL_MAX_BACKOFF_MS) so repeated loss doesn't retransmit
             * the same slot on consecutive ticks. */
            uint32_t shifts = slot->retry_count < 4 ? slot->retry_count : 4;
            uint64_t backoff = (uint64_t)rto_ms << shifts;
            if (backoff > NL_MAX_BACKOFF_MS) backoff = NL_MAX_BACKOFF_MS;
            if (now_ms - slot->send_time_ms < backoff) continue;

            if (slot->retry_count >= max_retries) {
                *out_give_up = true;
                continue;
            }

            emit_wire_for_slot(lane, channel_id, (uint8_t)d, slot, local_rwnd, retransmit, ctx);

            /* Reset the retransmit clock -- without this the same slot
             * would look "due" again on the very next tick and we'd fire
             * a retransmission storm instead of waiting another RTO. */
            slot->send_time_ms = now_ms;
            slot->retry_count++;
        }
    }
}
