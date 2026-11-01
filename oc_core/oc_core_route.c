#include "oc_core_route.h"

#include <stdio.h>
#include <string.h>

void oc_core_route_init(oc_core_route_t *r, uint16_t self)
{
    memset(r, 0, sizeof(*r));
    r->self = self;
}

static int nanp_code_ok(const char *c) /* NPA or NXX: 2-9 first, not N11 (numbering-plan.md v0.2) */
{
    return c[0] >= '2' && c[0] <= '9' && !(c[1] == '1' && c[2] == '1');
}

int oc_core_route_prefix_ok(const char *p)
{
    size_t n = strlen(p);
    if (n < 4 || n > OC_SIG_NUMBER_DIGITS || strncmp(p, "883", 3) != 0) return 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return 0;
    }
    if (p[3] != '1') return 1; /* not NANP: any 883-prefixed digit string in range */
    if (n != 7 && n != 10) return 0; /* NANP: NPA or NPA-NXX only */
    if (!nanp_code_ok(p + 4) || strncmp(p + 4, "883", 3) == 0) return 0; /* illegal or ambiguous NPA */
    return n != 10 || nanp_code_ok(p + 7); /* illegal NXX */
}

int oc_core_route_add_ex(oc_core_route_t *r, const char *prefix, uint16_t block_idx, uint16_t home_core,
                         uint16_t secondary, uint16_t tenant, const char *state)
{
    if (!oc_core_route_prefix_ok(prefix) || block_idx == 0 || r->n >= OC_CORE_BLOCKS) return -1;
    if (secondary != 0 && secondary == home_core) return -1;
    if (state != NULL && strlen(state) > OC_CORE_STATE_MAX) return -1;
    unsigned at = 0, lo = 0, hi = r->n;
    while (lo < hi) { /* the first block whose prefix is not below this one */
        unsigned mid = lo + (hi - lo) / 2u;
        if (strcmp(r->b[mid].prefix, prefix) < 0) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    at = lo;
    if (at < r->n && strcmp(r->b[at].prefix, prefix) == 0) return -1;
    for (unsigned i = 0; i < r->n; i++) {
        if (r->b[i].block_idx == block_idx) return -1;
    }
    memmove(&r->b[at + 1u], &r->b[at], (r->n - at) * sizeof(r->b[0]));
    r->n++;
    oc_core_block_t *b = &r->b[at];
    memset(b, 0, sizeof(*b));
    snprintf(b->prefix, sizeof(b->prefix), "%s", prefix);
    b->block_idx = block_idx;
    b->home_core = home_core;
    b->secondary = secondary;
    b->tenant = tenant;
    if (state != NULL) snprintf(b->state, sizeof(b->state), "%s", state);
    return 0;
}

int oc_core_route_add(oc_core_route_t *r, const char *prefix, uint16_t block_idx, uint16_t home_core)
{
    return oc_core_route_add_ex(r, prefix, block_idx, home_core, 0, 0, NULL);
}

/* The block whose prefix is exactly the first n digits of d, or NULL. */
static const oc_core_block_t *exact(const oc_core_route_t *r, const char *d, size_t n)
{
    unsigned lo = 0, hi = r->n;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2u;
        const char *p = r->b[mid].prefix;
        int c = strncmp(p, d, n);
        if (c == 0 && p[n] != '\0') c = 1; /* longer than n: after the n-digit one */
        if (c == 0) return &r->b[mid];
        if (c < 0) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return NULL;
}

const oc_core_block_t *oc_core_route_find(const oc_core_route_t *r, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    char text[OC_SIG_NUMBER_TEXT];
    if (!oc_sig_number_valid(number)) return NULL;
    oc_sig_number_to_text(number, text);
    size_t len = strlen(text + 1);
    for (size_t n = len < OC_SIG_NUMBER_DIGITS ? len : OC_SIG_NUMBER_DIGITS; n >= 4; n--) {
        const oc_core_block_t *b = exact(r, text + 1, n);
        if (b != NULL) return b;
    }
    return NULL;
}

const oc_core_block_t *oc_core_route_block(const oc_core_route_t *r, uint16_t block_idx)
{
    for (unsigned i = 0; i < r->n; i++) {
        if (r->b[i].block_idx == block_idx) return &r->b[i];
    }
    return NULL;
}

int oc_core_route_home(const oc_core_route_t *r, const oc_core_block_t *b)
{
    return b != NULL && b->home_core == r->self;
}

int oc_core_route_secondary(const oc_core_route_t *r, const oc_core_block_t *b)
{
    return b != NULL && b->secondary != 0 && b->secondary == r->self;
}

void oc_core_token_id(uint16_t block_idx, const uint8_t random6[6], uint8_t token_id[8])
{
    token_id[0] = (uint8_t)(block_idx >> 8);
    token_id[1] = (uint8_t)block_idx;
    memcpy(token_id + 2, random6, 6);
}

uint16_t oc_core_token_block(const uint8_t token_id[8])
{
    return (uint16_t)((token_id[0] << 8) | token_id[1]);
}

int oc_core_number_reserved(const uint8_t number[OC_SIG_NUMBER_LEN])
{
    char text[OC_SIG_NUMBER_TEXT];
    oc_sig_number_to_text(number, text);
    if (strlen(text) != 1 + 15 || text[4] != '1') return 0; /* not NANP */
    const char *sub = text + 11;
    return (sub[0] == '0' && sub[1] == '0') /* 00000-00999: 00000 and the service range */
           || strcmp(sub, "09911") == 0 || strcmp(sub, "99999") == 0;
}

int oc_core_number_pick(const oc_core_block_t *b, const uint8_t random[8], uint8_t number[OC_SIG_NUMBER_LEN])
{
    char d[OC_SIG_NUMBER_DIGITS + 1];
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
    return oc_sig_number_to_bcd(d, 15, number);
}
