/* seqbuf.h - sequence tracking data structures for the reliability layer.
 *
 * Three structures, each a fixed-size ring buffer indexed by
 * `sequence & (SIZE-1)` with a stored tag so stale slots from a previous
 * wrap of the 16-bit sequence space are detected instead of misread as
 * live data:
 *
 *   nl_send_ring_t    - unacked outgoing packets, kept around for
 *                        retransmission until acked or given up on.
 *   nl_recv_dedupe_t  - lightweight "have I seen sequence N" tracker,
 *                        also produces the 32-bit ack bitfield we piggyback
 *                        on outgoing packets.
 *   nl_reorder_ring_t - buffers reliable packets that arrived ahead of the
 *                        next expected in-order sequence, for channels
 *                        using NL_RELIABLE_ORDERED.
 *
 * All sequence numbers are uint16_t and wrap at 65536. Comparisons use
 * nl_seq_greater_than(), which handles wraparound correctly as long as the
 * two sequences being compared are never more than 32768 apart (true in
 * practice: the ring buffer size bounds how far sender/receiver can drift).
 */
#ifndef NETLINK_SEQBUF_H
#define NETLINK_SEQBUF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/netlink.h" /* NL_MAX_PACKET_SIZE */

#define NL_MAX_PACKET_SIZE_INTERNAL NL_MAX_PACKET_SIZE
#define NL_SEQ_RING_SIZE 256 /* must be a power of two */
#define NL_SEQ_RING_MASK (NL_SEQ_RING_SIZE - 1)

static inline bool nl_seq_greater_than(uint16_t s1, uint16_t s2) {
    /* Standard signed-wraparound sequence comparison (Fiedler-style). */
    return ((s1 > s2) && (uint16_t)(s1 - s2) <= 32768) ||
           ((s1 < s2) && (uint16_t)(s2 - s1) > 32768);
}

/* ---- send ring: stores payloads awaiting ack, for retransmission ---- */

typedef struct {
    uint16_t sequence;
    bool     valid;
    bool     acked;
    uint16_t len;
    uint64_t send_time_ms;
    uint32_t retry_count;
    uint8_t  data[NL_MAX_PACKET_SIZE_INTERNAL];
} nl_send_slot_t;

typedef struct {
    nl_send_slot_t *slots; /* heap allocated, NL_SEQ_RING_SIZE entries */
    uint16_t next_sequence;
    uint16_t unacked_count; /* valid && !acked slots; maintained by insert/ack
                             * so congestion control can gate on in-flight
                             * packets without rescanning the ring */
} nl_send_ring_t;

int  nl_send_ring_init(nl_send_ring_t *ring);
void nl_send_ring_free(nl_send_ring_t *ring);
/* Insert data at `next_sequence`, return the sequence used, and advance.
 * Returns false if len exceeds the max slot size, or if the target slot
 * still holds a live unacked packet (never overwrite un-retransmittable
 * state -- see seqbuf.c). */
bool nl_send_ring_insert(nl_send_ring_t *ring, const uint8_t *data, uint16_t len,
                          uint64_t now_ms, uint16_t *out_seq);
/* Mark `sequence` (and, per the ack-bitfield convention, the 32 preceding
 * sequences whose corresponding bit is set in ack_bits) as acked.
 *
 * If the exact `ack` sequence was newly acked by this call (not already
 * acked, i.e. this isn't a duplicate/stale ack) AND it was never
 * retransmitted (retry_count == 0), *out_has_rtt_sample is set true and
 * *out_rtt_sample_ms is set to the observed round-trip time. Only the
 * newest sequence is ever used as an RTT sample, and only when it was
 * never retransmitted -- this is Karn's algorithm: if a packet was
 * retransmitted, an incoming ack for it is ambiguous (you can't tell
 * which transmission it's acking), so sampling RTT from it would corrupt
 * the estimate, typically making it falsely low after a loss episode.
 * Older sequences newly-acked via the bitfield are never used as samples
 * for the same reason -- their delivery timing relative to `now_ms` says
 * as much about queueing/loss as about the path RTT.
 *
 * *out_newly_acked (optional) receives how many slots transitioned from
 * unacked to acked by this call -- the congestion controller's growth
 * signal. */
void nl_send_ring_ack(nl_send_ring_t *ring, uint16_t ack, uint32_t ack_bits, uint64_t now_ms,
                       bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms,
                       uint32_t *out_newly_acked);

/* Fast retransmit: scan for unacked slots that are almost certainly lost
 * rather than merely delayed/reordered, using the same signal TCP's
 * "three duplicate acks" heuristic uses -- if `reorder_threshold` or more
 * strictly-newer sequences are already confirmed acked (per `ack` and
 * `ack_bits`) while an older one isn't, waiting for the RTO timer is
 * pure wasted latency; the loss is already evident. Calls `emit` once
 * per sequence identified this way, marking it as retransmitted (bumping
 * retry_count and refreshing send_time_ms, exactly as a normal
 * RTO-triggered retransmit would) so it isn't immediately re-flagged.
 *
 * Whether a candidate slot is itself already acked is re-derived directly
 * from (ack, ack_bits) rather than solely trusted from slot->acked, so
 * this gives correct results independent of whether nl_send_ring_ack was
 * called first with these same values (real callers always do both
 * together with one incoming packet's ack/ack_bits, but correctness here
 * doesn't depend on that ordering). */
typedef void (*nl_fast_retransmit_fn)(void *ctx, uint16_t sequence);
void nl_send_ring_fast_retransmit(nl_send_ring_t *ring, uint16_t ack, uint32_t ack_bits,
                                   uint32_t reorder_threshold, uint64_t now_ms,
                                   nl_fast_retransmit_fn emit, void *ctx);
/* Look up an entry by exact sequence, for a caller that wants to inspect it
 * (e.g. retransmission scan). Returns NULL if not present/valid. */
nl_send_slot_t *nl_send_ring_get(nl_send_ring_t *ring, uint16_t sequence);

/* ---- receive dedupe: "have I seen this sequence" + ack bitfield ---- */

typedef struct {
    uint16_t sequence;
    bool     valid;
} nl_recv_slot_t;

typedef struct {
    nl_recv_slot_t *slots; /* heap allocated, NL_SEQ_RING_SIZE entries */
    uint16_t most_recent;
    bool     has_received_any;
} nl_recv_dedupe_t;

int  nl_recv_dedupe_init(nl_recv_dedupe_t *d);
void nl_recv_dedupe_free(nl_recv_dedupe_t *d);
/* Returns true if `sequence` is new (not previously seen and not too old
 * to track), and records it. Returns false for duplicates or packets so
 * old they've fallen out of the tracked window (treat as duplicates). */
bool nl_recv_dedupe_insert(nl_recv_dedupe_t *d, uint16_t sequence);
/* Produce the (ack, ack_bits) pair to piggyback on an outgoing packet,
 * describing everything received up through `most_recent`. */
void nl_recv_dedupe_build_ack(const nl_recv_dedupe_t *d, uint16_t *out_ack, uint32_t *out_ack_bits);

/* ---- reorder ring: buffers early-arriving reliable-ordered packets ---- */

typedef struct {
    uint16_t sequence;
    bool     valid;
    uint16_t len;
    uint8_t  data[NL_MAX_PACKET_SIZE_INTERNAL];
} nl_reorder_slot_t;

typedef struct {
    nl_reorder_slot_t *slots;
    uint16_t next_expected;
    bool     initialized;
} nl_reorder_ring_t;

int  nl_reorder_ring_init(nl_reorder_ring_t *ring);
void nl_reorder_ring_free(nl_reorder_ring_t *ring);
/* Buffer an out-of-order packet. Returns false if it's a duplicate of
 * something already buffered or already delivered (stale). */
bool nl_reorder_ring_insert(nl_reorder_ring_t *ring, uint16_t sequence, const uint8_t *data, uint16_t len);
/* Pop the next in-order packet if it's available (either just inserted or
 * previously buffered). Call repeatedly until it returns false -- multiple
 * packets can become deliverable at once when a gap-filling packet arrives. */
bool nl_reorder_ring_pop_ready(nl_reorder_ring_t *ring, uint8_t *out_data, uint16_t *out_len);

#endif /* NETLINK_SEQBUF_H */
