/* fragment.h - message fragmentation and reassembly.
 *
 * Splitting is stateless (just chunking a buffer). Reassembly is stateful
 * and receives attacker-controlled fields (fragment_count, fragment_index,
 * message_id) directly off the wire, so it is deliberately defensive:
 *
 *   - fragment_count is bounds-checked against NL_MAX_FRAGMENTS before any
 *     allocation happens.
 *   - the reassembled total size is bounds-checked against
 *     NL_MAX_MESSAGE_SIZE.
 *   - only a bounded number of reassemblies are in flight at once per
 *     tracker (oldest is evicted to make room for a new one, rather than
 *     growing unboundedly).
 *   - incomplete reassemblies older than NL_REASSEMBLY_TIMEOUT_MS are
 *     reclaimed even without eviction pressure.
 *   - the total in-flight reassembly size is budgeted per tracker
 *     (byte_budget): an incomplete message charges its full declared size
 *     at acquisition, and messages that would exceed the budget are
 *     rejected without displacing in-flight ones, so a hostile peer
 *     cannot multiply per-connection reassembly memory by spreading
 *     fragments across concurrent message ids.
 *
 * Fragmentation is meaningful with any delivery mode, but for UNRELIABLE
 * modes the loss of a single fragment discards the whole message (there is
 * no retry) -- callers sending large payloads should prefer a RELIABLE
 * delivery mode.
 */
#ifndef NETLINK_FRAGMENT_H
#define NETLINK_FRAGMENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/netlink.h"

#define NL_REASSEMBLY_SLOTS 4        /* concurrent in-flight messages per tracker */
#define NL_REASSEMBLY_TIMEOUT_MS 8000

/* Per-tracker budget on the SUM of the declared sizes (reserved at
 * acquisition) of in-flight reassembly messages. Sized so a single
 * maximum-size message can always reassemble, while a hostile peer
 * cannot pin arbitrarily more than that by spreading fragments across
 * concurrent message ids. nl_reassembly_tracker_init leaves the budget
 * unlimited (0) for unit tests; real connections apply this default in
 * nl_connection_create. */
#define NL_REASSEMBLY_BYTE_BUDGET_DEFAULT \
    ((uint32_t)NL_MAX_MESSAGE_SIZE + 2 * (uint32_t)NL_FRAGMENT_CHUNK_SIZE)

/* Maximum application payload bytes carried by a single wire fragment. */
#define NL_FRAGMENT_CHUNK_SIZE 1024

/* ---- sending: stateless chunking ---- */

/* Number of fragments required to send `message_len` bytes. Returns 0 if
 * message_len is 0 or exceeds NL_MAX_MESSAGE_SIZE. */
uint16_t nl_fragment_count_needed(size_t message_len);

/* Get a pointer + length for fragment `index` of a message. Caller must
 * have already validated index < nl_fragment_count_needed(total_len). */
void nl_fragment_get_chunk(const uint8_t *data, size_t total_len, uint16_t index,
                            const uint8_t **out_ptr, uint16_t *out_len);

/* ---- receiving: stateful reassembly ---- */

typedef struct {
    bool     active;
    uint16_t message_id;
    uint16_t fragment_count;
    uint16_t received_count;
    uint32_t total_len;      /* known once the last fragment (with a short chunk) arrives, else estimated */
    uint32_t received_bytes; /* payload bytes accepted into this slot so far */
    bool     total_len_known;
    uint64_t first_seen_ms;
    bool    *fragment_received;  /* heap array, fragment_count entries */
    uint8_t *data;                /* heap buffer, sized to the declared message (see fragment.c) */
    size_t   data_capacity;       /* allocated size of data, kept across messages */
    uint32_t reserved_bytes;      /* fragment_count x chunk size, charged to the tracker's budget */
} nl_reassembly_slot_t;

typedef struct {
    nl_reassembly_slot_t slots[NL_REASSEMBLY_SLOTS];
    /* Sum of reserved_bytes across ACTIVE slots. When acquiring a new
     * message would push this past byte_budget (if nonzero), the message
     * is rejected: a hostile peer cannot keep unboundedly many reassembly
     * buffers pinned by spreading fragments across message ids. */
    uint32_t in_flight_bytes;
    uint32_t byte_budget; /* 0 = unlimited (unit tests, plain tracker init) */
} nl_reassembly_tracker_t;

void nl_reassembly_tracker_init(nl_reassembly_tracker_t *t);

/* Same, with a per-tracker budget on the declared-size sum of in-flight
 * reassembly messages (0 = unlimited). Called by connection setup so each
 * connection's reassembly buffers stay within its own budget. */
void nl_reassembly_tracker_init_budget(nl_reassembly_tracker_t *t, uint32_t byte_budget);
void nl_reassembly_tracker_free(nl_reassembly_tracker_t *t);

typedef enum {
    NL_REASSEMBLE_INVALID,   /* malformed/out-of-bounds fields, drop the packet */
    NL_REASSEMBLE_PENDING,   /* fragment accepted, message not yet complete */
    NL_REASSEMBLE_COMPLETE,  /* message_id is now fully reassembled, see out params */
} nl_reassemble_result_t;

/* Feed one received fragment in. On NL_REASSEMBLE_COMPLETE, *out_data
 * points into internal storage (valid until the next call that reuses
 * this slot) and *out_len is the full message length. */
nl_reassemble_result_t nl_reassembly_feed(nl_reassembly_tracker_t *t, uint64_t now_ms,
                                           uint16_t message_id, uint16_t fragment_index,
                                           uint16_t fragment_count,
                                           const uint8_t *chunk, uint16_t chunk_len,
                                           const uint8_t **out_data, uint32_t *out_len);

/* Reclaim reassembly slots that have been incomplete for too long. Call
 * periodically (e.g. once per tick alongside retransmission scanning). */
void nl_reassembly_expire(nl_reassembly_tracker_t *t, uint64_t now_ms);

#endif /* NETLINK_FRAGMENT_H */
