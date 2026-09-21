/* channel.h - per (channel_id, delivery_mode) "lane" state.
 *
 * Each nl_channel_t represents one user-visible channel and internally
 * splits into up to 4 independent lanes, one per nl_delivery_t value,
 * allocated lazily on first use. This is what gives channels their
 * "don't block each other" property while still letting a single channel
 * carry a mix of delivery modes if the caller wants that: a lane used only
 * for NL_UNRELIABLE traffic never blocks on retransmission of a
 * NL_RELIABLE_ORDERED message sent on the same channel_id, because they
 * have entirely separate sequence spaces and buffers.
 *
 * This module knows nothing about sockets or encryption -- it operates on
 * plaintext wire payloads (the bytes that go inside the AEAD, after the
 * outer encrypted-packet header is stripped/added by connection.c). That
 * makes it independently testable by literally feeding one instance's
 * output into another's input, no network required.
 */
#ifndef NETLINK_CHANNEL_H
#define NETLINK_CHANNEL_H

#include <stdint.h>
#include <stdbool.h>
#include "seqbuf.h"
#include "fragment.h"
#include "protocol.h"
#include "../include/netlink.h"

#define NL_LANES_PER_CHANNEL 4 /* one per nl_delivery_t value */

typedef struct {
    nl_delivery_t delivery;
    bool          in_use;

    /* send side */
    uint16_t next_sequence;
    uint16_t next_message_id;
    nl_send_ring_t send_ring;     /* RELIABLE_* only */
    bool          send_ring_init;

    /* receive side */
    nl_recv_dedupe_t recv_dedupe; /* RELIABLE_* only: dedupe + ack bitfield source */
    bool          recv_dedupe_init;
    nl_reorder_ring_t reorder_ring; /* RELIABLE_ORDERED only */
    bool          reorder_ring_init;
    uint16_t      seq_highest_seen;      /* UNRELIABLE_SEQUENCED only */
    bool          seq_has_received_any;  /* UNRELIABLE_SEQUENCED only */
    nl_reassembly_tracker_t reassembly;  /* any mode carrying fragmented messages */
    bool          reassembly_init;
} nl_lane_t;

typedef struct {
    nl_lane_t lanes[NL_LANES_PER_CHANNEL];
} nl_channel_t;

void nl_channel_init(nl_channel_t *chan);
void nl_channel_free(nl_channel_t *chan);

/* Called when an outgoing reliable packet on this channel might need
 * retransmitting. Scans all reliable lanes' send rings for unacked entries
 * older than rto_ms and, for each, invokes `retransmit` with the fully
 * reconstructed wire payload (fresh piggybacked ack/ack_bits). */
typedef void (*nl_channel_retransmit_fn)(void *ctx, const uint8_t *wire_payload, uint16_t len);
void nl_channel_tick(nl_channel_t *chan, uint8_t channel_id, uint64_t now_ms, uint32_t rto_ms,
                      uint32_t max_retries, nl_channel_retransmit_fn retransmit, void *ctx,
                      bool *out_give_up);

/* Encode and hand off (via `emit`) one or more wire DATA payloads carrying
 * `data`/`len` on `channel_id` using `delivery`. Splits into fragments
 * automatically if the message is too large for one packet. `emit` is
 * called once per resulting wire packet, in order. */
typedef void (*nl_channel_emit_fn)(void *ctx, const uint8_t *wire_payload, uint16_t len);
nl_result_t nl_channel_send(nl_channel_t *chan, uint64_t now_ms, uint8_t channel_id, nl_delivery_t delivery,
                             const uint8_t *data, size_t len,
                             nl_channel_emit_fn emit, void *ctx);

/* Feed one received (already-decrypted) wire DATA payload in. Any
 * piggybacked ack/ack_bits are applied to this lane's send ring
 * immediately, and (for reliable lanes) checked for a fast-retransmit
 * condition -- an unacked sequence with NL_FAST_RETRANSMIT_THRESHOLD or
 * more strictly-newer sequences already confirmed acked is retransmitted
 * immediately via `retransmit`/`retransmit_ctx` rather than waiting for
 * the RTO timer, since the loss is already evident (the same signal
 * behind TCP's "three duplicate acks" fast retransmit). `retransmit` may
 * be NULL to skip this (e.g. from a test that doesn't care).
 *
 * If the ack corresponds to a clean RTT sample (see nl_send_ring_ack's
 * doc comment on Karn's algorithm), *out_has_rtt_sample is set true and
 * *out_rtt_sample_ms holds it; both may be NULL if the caller doesn't need this.
 *
 * Any fully-formed application message(s) that become deliverable as a
 * result (immediately, or released from the reorder buffer) are handed
 * to `deliver`, in delivery order. */
typedef void (*nl_channel_deliver_fn)(void *ctx, uint8_t channel_id, nl_delivery_t delivery,
                                       const uint8_t *data, uint32_t len);
#define NL_FAST_RETRANSMIT_THRESHOLD 3 /* matches TCP's conventional "3 duplicate acks" */
void nl_channel_on_receive(nl_channel_t *chan, uint64_t now_ms,
                            const uint8_t *wire_payload, uint16_t wire_len,
                            nl_channel_deliver_fn deliver, void *deliver_ctx,
                            nl_channel_retransmit_fn retransmit, void *retransmit_ctx,
                            bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms);

#endif /* NETLINK_CHANNEL_H */
