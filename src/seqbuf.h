/* seqbuf.h - sequence tracking data structures for the reliability layer.
 *
 * Three structures, each a fixed-size ring buffer indexed by
 * `sequence & (SIZE-1)` with a stored tag so stale slots from a previous
 * wrap of the 16-bit sequence space are detected instead of misread as
 * live data:
 *
 *   wn_send_ring_t    - unacked outgoing packets, kept around for
 *                        retransmission until acked or given up on.
 *   wn_recv_dedupe_t  - lightweight "have I seen sequence N" tracker,
 *                        also produces the WN_ACK_WINDOW_BITS-bit ack
 *                        bitfield we piggyback on outgoing packets.
 *   wn_reorder_ring_t - buffers reliable packets that arrived ahead of the
 *                        next expected in-order sequence, for channels
 *                        using WN_RELIABLE_ORDERED.
 *
 * All sequence numbers are uint16_t and wrap at 65536. Comparisons use
 * wn_seq_greater_than(), which handles wraparound correctly as long as the
 * two sequences being compared are never more than 32768 apart (true in
 * practice: the ring buffer size bounds how far sender/receiver can drift).
 */
#ifndef WEFT_NET_SEQBUF_H
#define WEFT_NET_SEQBUF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/weft_net.h" /* WN_MAX_PACKET_SIZE */

#define WN_MAX_PACKET_SIZE_INTERNAL WN_MAX_PACKET_SIZE
#define WN_SEQ_RING_SIZE 256 /* must be a power of two */
#define WN_SEQ_RING_MASK (WN_SEQ_RING_SIZE - 1)
/* How many sequences below the receiver's newest one an ack can name.
 * This is the ack bitmap's width, and therefore the hard ceiling on how
 * many reliable packets may be in flight: a still-unacked sequence that
 * falls further back than this can never be named by any future ack, so it
 * would burn its entire retry budget and then tear the connection down
 * even though the receiver has it. connection.h's congestion-window bounds
 * must therefore never exceed this.
 *
 * 64 rather than 32 so a comfortable window is nameable without making the
 * in-flight ceiling the binding constraint on throughput; the send ring is
 * 256 deep, so the receiver's tracking comfortably covers it. */
#define WN_ACK_WINDOW_BITS 64

static inline bool wn_seq_greater_than(uint16_t s1, uint16_t s2) {
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
    /* This slot has already been fast-retransmitted once and is waiting to
     * be acked. Cleared by ack_one(); set by wn_send_ring_fast_retransmit.
     * Without it, every inbound packet whose ack horizon is far enough
     * ahead re-fires a retransmit for the same hole. */
    bool     fast_retx_done;
    uint8_t  data[WN_MAX_PACKET_SIZE_INTERNAL];
} wn_send_slot_t;

typedef struct {
    wn_send_slot_t *slots; /* heap allocated, WN_SEQ_RING_SIZE entries */
    uint16_t next_sequence;
    uint16_t unacked_count; /* valid && !acked slots; maintained by insert/ack
                             * so congestion control can gate on in-flight
                             * packets without rescanning the ring */
} wn_send_ring_t;

int  wn_send_ring_init(wn_send_ring_t *ring);
void wn_send_ring_free(wn_send_ring_t *ring);
/* Bits in the ack bitmap (WN_ACK_WINDOW_BITS), so callers don't repeat the
 * width as a literal at each call site. */
typedef uint64_t wn_ack_bits_t;

/* Insert data at `next_sequence`, return the sequence used, and advance.
 * Returns false if len exceeds the max slot size, or if the target slot
 * still holds a live unacked packet (never overwrite un-retransmittable
 * state -- see seqbuf.c). */
bool wn_send_ring_insert(wn_send_ring_t *ring, const uint8_t *data, uint16_t len,
                          uint64_t now_ms, uint16_t *out_seq);
/* Mark `sequence` (and, per the ack-bitfield convention, the
 * WN_ACK_WINDOW_BITS preceding sequences whose corresponding bit is set in
 * ack_bits) as acked.
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
 * signal.
 *
 * *out_has_rtt_sample is left false when `now_ms` precedes the slot's
 * send_time_ms: an RTT sample is a duration, and a backwards clock reading
 * cannot produce one. The slot is still marked acked. */
void wn_send_ring_ack(wn_send_ring_t *ring, uint16_t ack, wn_ack_bits_t ack_bits, uint64_t now_ms,
                       bool *out_has_rtt_sample, uint32_t *out_rtt_sample_ms,
                       uint32_t *out_newly_acked);

/* Fast retransmit: scan for unacked slots that are almost certainly lost
 * rather than merely delayed/reordered, using the same signal TCP's
 * "three duplicate acks" heuristic uses -- if `reorder_threshold` or more
 * strictly-newer sequences are already confirmed acked (per `ack` and
 * `ack_bits`) while an older one isn't, waiting for the RTO timer is
 * pure wasted latency; the loss is already evident. Calls `emit` at most
 * once per sequence: a slot already fast-retransmitted is skipped until
 * it's acked, since every further inbound packet with an advanced ack
 * horizon would otherwise re-fire the same retransmission. The RTO clock
 * (send_time_ms) is refreshed so the RTO scan doesn't immediately fire
 * for the same slot too; retry_count is deliberately left alone, as that
 * is the give-up budget and charging it here would let ordinary loss
 * recovery exhaust it.
 *
 * Whether a candidate slot is itself already acked is re-derived directly
 * from (ack, ack_bits) rather than solely trusted from slot->acked, so
 * this gives correct results independent of whether wn_send_ring_ack was
 * called first with these same values (real callers always do both
 * together with one incoming packet's ack/ack_bits, but correctness here
 * doesn't depend on that ordering). */
typedef void (*wn_fast_retransmit_fn)(void *ctx, uint16_t sequence);
void wn_send_ring_fast_retransmit(wn_send_ring_t *ring, uint16_t ack, wn_ack_bits_t ack_bits,
                                   uint32_t reorder_threshold, uint64_t now_ms,
                                   wn_fast_retransmit_fn emit, void *ctx);
/* Look up an entry by exact sequence, for a caller that wants to inspect it
 * (e.g. retransmission scan). Returns NULL if not present/valid. */
wn_send_slot_t *wn_send_ring_get(wn_send_ring_t *ring, uint16_t sequence);
/* Oldest sequence still awaiting an ack, or ring->next_sequence if nothing
 * is outstanding. The *span* from here to next_sequence -- not the count of
 * unacked slots -- is what an ack must be able to reach, so congestion
 * control has to gate on it: counting unacked packets understates the
 * window whenever earlier packets are still missing. */
uint16_t wn_send_ring_oldest_unacked(const wn_send_ring_t *ring);

/* ---- receive dedupe: "have I seen this sequence" + ack bitfield ---- */

typedef struct {
    uint16_t sequence;
    bool     valid;
} wn_recv_slot_t;

typedef struct {
    wn_recv_slot_t *slots; /* heap allocated, WN_SEQ_RING_SIZE entries */
    uint16_t most_recent;
    bool     has_received_any;
} wn_recv_dedupe_t;

int  wn_recv_dedupe_init(wn_recv_dedupe_t *d);
void wn_recv_dedupe_free(wn_recv_dedupe_t *d);
/* Returns true if `sequence` is new (not previously seen and not too old
 * to track), and records it. Returns false for duplicates or packets so
 * old they've fallen out of the tracked window (treat as duplicates). */
bool wn_recv_dedupe_insert(wn_recv_dedupe_t *d, uint16_t sequence);
/* Read-only counterpart of wn_recv_dedupe_insert: true if inserting
 * `sequence` would report a duplicate (already recorded, or too old to be
 * tracked). Never modifies the window, so a caller can decide whether to
 * accept a packet before it becomes visible in the ack. */
bool wn_recv_dedupe_seen(const wn_recv_dedupe_t *d, uint16_t sequence);
/* Produce the (ack, ack_bits) pair to piggyback on an outgoing packet,
 * describing everything received up through `most_recent`. */
void wn_recv_dedupe_build_ack(const wn_recv_dedupe_t *d, uint16_t *out_ack, wn_ack_bits_t *out_ack_bits);

/* ---- reorder ring: buffers early-arriving reliable-ordered packets ---- */

typedef struct {
    uint16_t sequence;
    bool     valid;
    uint16_t len;
    uint8_t  data[WN_MAX_PACKET_SIZE_INTERNAL];
} wn_reorder_slot_t;

typedef struct {
    wn_reorder_slot_t *slots;
    uint16_t next_expected;
    bool     initialized;
} wn_reorder_ring_t;

int  wn_reorder_ring_init(wn_reorder_ring_t *ring);
void wn_reorder_ring_free(wn_reorder_ring_t *ring);
/* True when `sequence` is close enough behind/ahead of next_expected that
 * wn_reorder_ring_insert can actually buffer it. Far ahead is the only
 * unrecoverable case: a stale or already-buffered sequence will resolve
 * itself (it was delivered, or is already waiting its turn), but one beyond
 * the window is dropped outright and must never be acked -- acking it tells
 * the sender to stop retransmitting a packet that will never be delivered,
 * and for RELIABLE_ORDERED it wedges next_expected behind the gap forever.
 * Exposed so callers can make that decision without duplicating the rule. */
bool wn_reorder_ring_reachable(const wn_reorder_ring_t *ring, uint16_t sequence);
/* Buffer an out-of-order packet. Returns false if it's a duplicate of
 * something already buffered or already delivered (stale), or if it's too
 * far ahead to fit the window (see wn_reorder_ring_reachable). */
bool wn_reorder_ring_insert(wn_reorder_ring_t *ring, uint16_t sequence, const uint8_t *data, uint16_t len);
/* Pop the next in-order packet if it's available (either just inserted or
 * previously buffered). Call repeatedly until it returns false -- multiple
 * packets can become deliverable at once when a gap-filling packet arrives. */
bool wn_reorder_ring_pop_ready(wn_reorder_ring_t *ring, uint8_t *out_data, uint16_t *out_len);

#endif /* WEFT_NET_SEQBUF_H */
