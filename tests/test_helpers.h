/* test_helpers.h - declarations for test-only helpers exported by the
 * library sources. These symbols are NOT part of the ABI and must not be
 * used outside the test suite: they reach into endpoint internals so
 * regression tests can assert invariants the public API (deliberately)
 * does not expose.
 */
#ifndef WEFT_NET_TEST_HELPERS_H
#define WEFT_NET_TEST_HELPERS_H

#include <stddef.h>
#include "../include/weft_net.h"

/* Number of in-use pending-handshake slots. Lets regression tests assert
 * a failed connect does not leak its entry. */
int wn_endpoint_pending_used_for_test(wn_endpoint_t *ep);

/* Total payload bytes currently queued endpoint-wide (the
 * wn_config_t.event_queue_max_bytes cap target). */
size_t wn_endpoint_event_queue_bytes_for_test(wn_endpoint_t *ep);

/* Number of live WebSocket links (either side). Lets regression tests
 * assert the idle-link reap sweep closes links that never get anywhere. */
int wn_endpoint_ws_links_used_for_test(wn_endpoint_t *ep);

#endif /* WEFT_NET_TEST_HELPERS_H */
