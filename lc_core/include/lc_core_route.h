/* The block table as one core sees it (network-core spec §14.2-14.3), and
 * the number policy that goes with it (§7.11, numbering-plan.md v0.2).
 *
 * A block is a prefix of the full form (883 . CC . NPA, or 883 . CC . NPA .
 * NXX) with a block index that is never reused and a home core. The longest
 * prefix wins, so an exchange block can sit inside another tenant's area
 * code. For now one core runs with every block at home; plans 10-11 add the
 * signed table, secondaries, epochs and takeovers around the same lookups. */
#ifndef LC_CORE_ROUTE_H
#define LC_CORE_ROUTE_H

#include "lc_sig.h"

#define LC_CORE_BLOCKS 32u

typedef struct {
    char     prefix[LC_SIG_NUMBER_DIGITS + 1]; /* digits only, e.g. "8831606" */
    uint16_t block_idx;                        /* 1-65535, never reused */
    uint16_t home_core;                        /* core_id */
} lc_core_block_t;

typedef struct {
    uint16_t        self; /* this core's core_id */
    lc_core_block_t b[LC_CORE_BLOCKS];
    unsigned        n;
} lc_core_route_t;

void lc_core_route_init(lc_core_route_t *r, uint16_t self);
/* 0, or -1: a prefix that is not digits starting 883 (4-15 digits; a NANP
 * prefix is NPA or NPA-NXX: 7 or 10 digits, with a legal NPA and, for
 * NPA-NXX, a legal NXX too: 2-9 first digit, not N11, and the NPA not 883 -
 * the same rules lc_sig applies, numbering-plan.md v0.2), block index 0, a
 * prefix or index already in the table, or a full table. */
int lc_core_route_add(lc_core_route_t *r, const char *prefix, uint16_t block_idx, uint16_t home_core);
/* The block with the longest prefix of number, or NULL (no route). */
const lc_core_block_t *lc_core_route_find(const lc_core_route_t *r, const uint8_t number[LC_SIG_NUMBER_LEN]);
const lc_core_block_t *lc_core_route_block(const lc_core_route_t *r, uint16_t block_idx);
/* 1 if b is a block this core is home for ("am I home?"); 0 for NULL. */
int lc_core_route_home(const lc_core_route_t *r, const lc_core_block_t *b);

/* Token ids carry their block (§14.3): the block index big-endian in bytes
 * 0-1, then 6 random bytes (the tag, keyed by the token secret, carries the
 * security). */
void     lc_core_token_id(uint16_t block_idx, const uint8_t random6[6], uint8_t token_id[8]);
uint16_t lc_core_token_block(const uint8_t token_id[8]);

/* 1 for a number no subscriber may have: a NANP subscriber part 00000,
 * 00911, 09911, 99999 or the service range 00001-00999 (service numbers such
 * as the echo service are configured, not assigned). Other country codes have
 * no reserved numbers yet. */
int lc_core_number_reserved(const uint8_t number[LC_SIG_NUMBER_LEN]);

/* A random candidate in block b (NANP blocks only): a random NXX when the
 * prefix is an NPA, then a subscriber part in 01000-99998, never 09911.
 * random: 8 random bytes. 0, or -1 when b is not a NANP block. The caller
 * checks that the number is free. */
int lc_core_number_pick(const lc_core_block_t *b, const uint8_t random[8], uint8_t number[LC_SIG_NUMBER_LEN]);

#endif
