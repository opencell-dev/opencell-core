#include "lc_core_route.h"

#include <stdio.h>
#include <string.h>

void lc_core_route_init(lc_core_route_t *r, uint16_t self)
{
    memset(r, 0, sizeof(*r));
    r->self = self;
}

static int nanp_code_ok(const char *c) /* NPA or NXX: 2-9 first, not N11 (numbering-plan.md v0.2) */
{
    return c[0] >= '2' && c[0] <= '9' && !(c[1] == '1' && c[2] == '1');
}

static int prefix_ok(const char *p)
{
    size_t n = strlen(p);
    if (n < 4 || n > LC_SIG_NUMBER_DIGITS || strncmp(p, "883", 3) != 0) return 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return 0;
    }
    if (p[3] != '1') return 1; /* not NANP: any 883-prefixed digit string in range */
    if (n != 7 && n != 10) return 0; /* NANP: NPA or NPA-NXX only */
    if (!nanp_code_ok(p + 4) || strncmp(p + 4, "883", 3) == 0) return 0; /* illegal or ambiguous NPA */
    return n != 10 || nanp_code_ok(p + 7); /* illegal NXX */
}

int lc_core_route_add(lc_core_route_t *r, const char *prefix, uint16_t block_idx, uint16_t home_core)
{
    if (!prefix_ok(prefix) || block_idx == 0 || r->n >= LC_CORE_BLOCKS) return -1;
    for (unsigned i = 0; i < r->n; i++) {
        if (strcmp(r->b[i].prefix, prefix) == 0 || r->b[i].block_idx == block_idx) return -1;
    }
    lc_core_block_t *b = &r->b[r->n++];
    snprintf(b->prefix, sizeof(b->prefix), "%s", prefix);
    b->block_idx = block_idx;
    b->home_core = home_core;
    return 0;
}

const lc_core_block_t *lc_core_route_find(const lc_core_route_t *r, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    char text[LC_SIG_NUMBER_TEXT];
    const lc_core_block_t *best = NULL;
    if (!lc_sig_number_valid(number)) return NULL;
    lc_sig_number_to_text(number, text);
    for (unsigned i = 0; i < r->n; i++) {
        size_t n = strlen(r->b[i].prefix);
        if (strncmp(text + 1, r->b[i].prefix, n) == 0 && (best == NULL || n > strlen(best->prefix))) best = &r->b[i];
    }
    return best;
}

const lc_core_block_t *lc_core_route_block(const lc_core_route_t *r, uint16_t block_idx)
{
    for (unsigned i = 0; i < r->n; i++) {
        if (r->b[i].block_idx == block_idx) return &r->b[i];
    }
    return NULL;
}

int lc_core_route_home(const lc_core_route_t *r, const lc_core_block_t *b)
{
    return b != NULL && b->home_core == r->self;
}

void lc_core_token_id(uint16_t block_idx, const uint8_t random6[6], uint8_t token_id[8])
{
    token_id[0] = (uint8_t)(block_idx >> 8);
    token_id[1] = (uint8_t)block_idx;
    memcpy(token_id + 2, random6, 6);
}

uint16_t lc_core_token_block(const uint8_t token_id[8])
{
    return (uint16_t)((token_id[0] << 8) | token_id[1]);
}

int lc_core_number_reserved(const uint8_t number[LC_SIG_NUMBER_LEN])
{
    char text[LC_SIG_NUMBER_TEXT];
    lc_sig_number_to_text(number, text);
    if (strlen(text) != 1 + 15 || text[4] != '1') return 0; /* not NANP */
    const char *sub = text + 11;
    return (sub[0] == '0' && sub[1] == '0') /* 00000-00999: 00000 and the service range */
           || strcmp(sub, "09911") == 0 || strcmp(sub, "99999") == 0;
}

int lc_core_number_pick(const lc_core_block_t *b, const uint8_t random[8], uint8_t number[LC_SIG_NUMBER_LEN])
{
    char d[LC_SIG_NUMBER_DIGITS + 1];
    size_t n = strlen(b->prefix);
    if (n < 4 || b->prefix[3] != '1' || (n != 7 && n != 10)) return -1;
    memcpy(d, b->prefix, n);
    if (n == 7) { /* NXX: 2-9 first, not N11 */
        unsigned nxx = 200u + ((unsigned)random[0] << 8 | random[1]) % 800u;
        if (nxx % 100u == 11u) nxx++;
        for (int i = 9; i >= 7; i--, nxx /= 10u) d[i] = (char)('0' + nxx % 10u);
    }
    unsigned sub = 1000u + ((unsigned)random[2] << 16 | (unsigned)random[3] << 8 | random[4]) % 98999u;
    if (sub == 9911u) sub++;
    for (int i = 14; i >= 10; i--, sub /= 10u) d[i] = (char)('0' + sub % 10u);
    return lc_sig_number_to_bcd(d, 15, number);
}
