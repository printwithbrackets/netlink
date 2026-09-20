/* byteorder.h - safe, alignment-agnostic big-endian read/write helpers.
 *
 * We never cast a raw byte pointer to a struct/int pointer and dereference
 * it: on some platforms that's undefined behavior (strict aliasing) or a
 * crash (alignment faults on ARM/SPARC). These helpers do byte-at-a-time
 * access, which every compiler turns into a single load/store instruction
 * on platforms that support unaligned access anyway.
 */
#ifndef NETLINK_BYTEORDER_H
#define NETLINK_BYTEORDER_H

#include <stdint.h>
#include <string.h>

static inline void nl_put_u8(uint8_t *p, uint8_t v) { p[0] = v; }
static inline uint8_t nl_get_u8(const uint8_t *p) { return p[0]; }

static inline void nl_put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}
static inline uint16_t nl_get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void nl_put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}
static inline uint32_t nl_get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void nl_put_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static inline uint64_t nl_get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

#endif /* NETLINK_BYTEORDER_H */
