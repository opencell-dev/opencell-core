#include "oc_rtbl.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

const char *const OC_RTBL_EAST[] = {
    "US-AL", "US-CT", "US-DC", "US-DE", "US-FL", "US-GA", "US-IL", "US-IN", "US-KY", "US-MA", "US-MD", "US-ME",
    "US-MI", "US-MS", "US-NC", "US-NH", "US-NJ", "US-NY", "US-OH", "US-PA", "US-RI", "US-SC", "US-TN", "US-VA",
    "US-VT", "US-WI", "US-WV", "US-PR", "US-VI", "CA-ON", "CA-QC", "CA-NB", "CA-NS", "CA-PE", "CA-NL", "AG",
    "AI",    "BB",    "BM",    "BS",    "DM",    "DO",    "GD",    "JM",    "KN",    "KY",    "LC",    "MS",
    "SX",    "TC",    "TT",    "VC",    "VG",    NULL
};
const char *const OC_RTBL_WEST[] = {
    "US-AK", "US-AR", "US-AZ", "US-CA", "US-CO", "US-HI", "US-IA", "US-ID", "US-KS", "US-LA", "US-MN", "US-MO",
    "US-MT", "US-ND", "US-NE", "US-NM", "US-NV", "US-OK", "US-OR", "US-SD", "US-TX", "US-UT", "US-WA", "US-WY",
    "US-GU", "US-MP", "US-AS", "CA-MB", "CA-SK", "CA-AB", "CA-BC", "CA-YT", "CA-NT", "CA-NU", NULL
};

static void errf(char *err, size_t cap, const char *fmt, ...)
{
    va_list ap;
    if (err == NULL || cap == 0) return;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int up(char c) { return c >= 'A' && c <= 'Z'; }

int oc_rtbl_state_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 2) return up(s[0]) && up(s[1]);
    if (n != 5 || s[2] != '-' || !up(s[3]) || !up(s[4])) return 0;
    return (s[0] == 'U' && s[1] == 'S') || (s[0] == 'C' && s[1] == 'A');
}

/* ---- the byte reader and writer ---- */

typedef struct {
    const uint8_t *p;
    size_t         n, at;
    int            bad;
} rd_t;

static uint8_t r8(rd_t *r)
{
    if (r->at >= r->n) {
        r->bad = 1;
        return 0;
    }
    return r->p[r->at++];
}
static uint16_t r16(rd_t *r) { uint16_t lo = r8(r); return (uint16_t)(lo | (uint16_t)(r8(r) << 8)); }
static uint32_t r32(rd_t *r) { uint32_t lo = r16(r); return lo | ((uint32_t)r16(r) << 16); }
static void rb(rd_t *r, uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) b[i] = r8(r);
}
/* text of at most max bytes into out (max + 1), printable ASCII only */
static void rtext(rd_t *r, char *out, size_t max)
{
    uint8_t n = r8(r);
    if (n > max) {
        r->bad = 1;
        n = 0;
    }
    for (uint8_t i = 0; i < n; i++) {
        char c = (char)r8(r);
        if (c < 0x20 || c > 0x7e) r->bad = 1;
        out[i] = c;
    }
    out[n] = '\0';
}

typedef struct {
    uint8_t *p;
    size_t   n, cap;
    int      bad;
} wr_t;

static void w8(wr_t *w, uint8_t v)
{
    if (w->n >= w->cap) {
        w->bad = 1;
        return;
    }
    w->p[w->n++] = v;
}
static void w16(wr_t *w, uint16_t v) { w8(w, (uint8_t)v); w8(w, (uint8_t)(v >> 8)); }
static void w32(wr_t *w, uint32_t v) { w16(w, (uint16_t)v); w16(w, (uint16_t)(v >> 16)); }
static void wb(wr_t *w, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) w8(w, b[i]);
}
static void wtext(wr_t *w, const char *s)
{
    size_t n = strlen(s);
    if (n > 255) {
        w->bad = 1;
        return;
    }
    w8(w, (uint8_t)n);
    wb(w, (const uint8_t *)s, n);
}

/* ---- the root table ---- */

static int in_dir(const oc_rtbl_root_t *t, uint16_t id)
{
    for (unsigned i = 0; i < t->ncores; i++) {
        if (t->cores[i].id == id) return 1;
    }
    return 0;
}

int oc_rtbl_root_decode(const uint8_t *blob, size_t n, oc_rtbl_root_t *t, char *err, size_t cap)
{
    rd_t r = { blob, n, 0, 0 };
    uint8_t magic[4];
    memset(t, 0, sizeof(*t));
    rb(&r, magic, 4);
    if (r.bad || memcmp(magic, "OCRT", 4) != 0 || r8(&r) != 1) {
        errf(err, cap, "not a root table (magic OCRT, format 1)");
        return -1;
    }
    t->version = r32(&r);
    t->issued = r32(&r);
    t->max_idx = r16(&r);
    t->ncores = r8(&r);
    if (r.bad || t->version == 0 || t->ncores == 0 || t->ncores > OC_RTBL_CORES) {
        errf(err, cap, "malformed header (version >= 1, 1-%u cores)", OC_RTBL_CORES);
        return -1;
    }
    for (unsigned i = 0; i < t->ncores; i++) {
        oc_rtbl_core_t *c = &t->cores[i];
        c->id = r16(&r);
        rtext(&r, c->name, sizeof(c->name) - 1u);
        if (r.bad || c->id == 0 || c->name[0] == '\0') {
            errf(err, cap, "core %u: malformed", i);
            return -1;
        }
        for (unsigned j = 0; j < i; j++) {
            if (t->cores[j].id == c->id) {
                errf(err, cap, "core %u named twice", c->id);
                return -1;
            }
        }
    }
    t->nblocks = r16(&r);
    if (r.bad || t->nblocks == 0 || t->nblocks > OC_CORE_BLOCKS) {
        errf(err, cap, "1-%u blocks", OC_CORE_BLOCKS);
        return -1;
    }
    for (unsigned i = 0; i < t->nblocks; i++) {
        oc_rtbl_block_t *b = &t->blocks[i];
        rtext(&r, b->prefix, OC_SIG_NUMBER_DIGITS);
        b->idx = r16(&r);
        b->tenant = r16(&r);
        b->home = r16(&r);
        b->nsec = r8(&r);
        if (b->nsec > 2) r.bad = 1;
        for (unsigned s = 0; s < b->nsec && !r.bad; s++) b->sec[s] = r16(&r);
        b->epoch = r16(&r);
        rtext(&r, b->state, OC_CORE_STATE_MAX);
        if (r.bad || !oc_core_route_prefix_ok(b->prefix) || b->idx == 0 || b->idx > t->max_idx || b->tenant == 0 ||
            !in_dir(t, b->home) || b->epoch == 0 || (b->state[0] != '\0' && !oc_rtbl_state_ok(b->state))) {
            errf(err, cap, "block %u (%s): malformed or out of range", i, r.bad ? "?" : b->prefix);
            return -1;
        }
        for (unsigned s = 0; s < b->nsec; s++) {
            if (!in_dir(t, b->sec[s]) || b->sec[s] == b->home || (s == 1 && b->sec[1] == b->sec[0])) {
                errf(err, cap, "block %s: bad secondary", b->prefix);
                return -1;
            }
        }
    }
    t->ndeleg = r8(&r);
    if (r.bad || t->ndeleg > OC_RTBL_DELEGS) {
        errf(err, cap, "0-%u delegations", OC_RTBL_DELEGS);
        return -1;
    }
    for (unsigned i = 0; i < t->ndeleg; i++) {
        oc_rtbl_deleg_t *d = &t->deleg[i];
        rb(&r, d->pub, OC_RTBL_KEY);
        d->scope = r8(&r);
        d->not_before = r32(&r);
        d->not_after = r32(&r);
        d->tenant = r16(&r);
        d->east = r16(&r);
        d->west = r16(&r);
        d->neast = r8(&r);
        if (d->neast > OC_RTBL_STATES) r.bad = 1;
        for (unsigned s = 0; s < d->neast && !r.bad; s++) rtext(&r, d->east_st[s], OC_CORE_STATE_MAX);
        d->nwest = r8(&r);
        if (d->nwest > OC_RTBL_STATES) r.bad = 1;
        for (unsigned s = 0; s < d->nwest && !r.bad; s++) rtext(&r, d->west_st[s], OC_CORE_STATE_MAX);
        if (r.bad || !in_dir(t, d->east) || !in_dir(t, d->west) || d->east == d->west || d->tenant == 0) {
            errf(err, cap, "delegation %u: malformed", i);
            return -1;
        }
        for (unsigned s = 0; s < d->neast; s++) {
            if (!oc_rtbl_state_ok(d->east_st[s])) r.bad = 1;
        }
        for (unsigned s = 0; s < d->nwest; s++) {
            if (!oc_rtbl_state_ok(d->west_st[s])) r.bad = 1;
        }
        if (r.bad) {
            errf(err, cap, "delegation %u: a bad state code", i);
            return -1;
        }
    }
    t->nrevoked = r8(&r);
    if (t->nrevoked > OC_RTBL_REVOKED) r.bad = 1;
    for (unsigned i = 0; i < t->nrevoked && !r.bad; i++) rb(&r, t->revoked[i], OC_RTBL_KEY);
    if (r.bad || r.at != n) {
        errf(err, cap, "malformed tail (revoked keys, or bytes after the end)");
        return -1;
    }
    for (unsigned i = 0; i < t->nblocks; i++) { /* unique prefixes and indexes */
        for (unsigned j = 0; j < i; j++) {
            if (strcmp(t->blocks[i].prefix, t->blocks[j].prefix) == 0 || t->blocks[i].idx == t->blocks[j].idx) {
                errf(err, cap, "block %s: its prefix or index again", t->blocks[i].prefix);
                return -1;
            }
        }
    }
    return 0;
}

size_t oc_rtbl_root_encode(const oc_rtbl_root_t *t, uint8_t *out, size_t cap)
{
    wr_t w = { out, 0, cap, 0 };
    wb(&w, (const uint8_t *)"OCRT", 4);
    w8(&w, 1);
    w32(&w, t->version);
    w32(&w, t->issued);
    w16(&w, t->max_idx);
    w8(&w, t->ncores);
    for (unsigned i = 0; i < t->ncores; i++) {
        w16(&w, t->cores[i].id);
        wtext(&w, t->cores[i].name);
    }
    w16(&w, t->nblocks);
    for (unsigned i = 0; i < t->nblocks; i++) {
        const oc_rtbl_block_t *b = &t->blocks[i];
        wtext(&w, b->prefix);
        w16(&w, b->idx);
        w16(&w, b->tenant);
        w16(&w, b->home);
        w8(&w, b->nsec);
        for (unsigned s = 0; s < b->nsec && s < 2; s++) w16(&w, b->sec[s]);
        w16(&w, b->epoch);
        wtext(&w, b->state);
    }
    w8(&w, t->ndeleg);
    for (unsigned i = 0; i < t->ndeleg; i++) {
        const oc_rtbl_deleg_t *d = &t->deleg[i];
        wb(&w, d->pub, OC_RTBL_KEY);
        w8(&w, d->scope);
        w32(&w, d->not_before);
        w32(&w, d->not_after);
        w16(&w, d->tenant);
        w16(&w, d->east);
        w16(&w, d->west);
        w8(&w, d->neast);
        for (unsigned s = 0; s < d->neast; s++) wtext(&w, d->east_st[s]);
        w8(&w, d->nwest);
        for (unsigned s = 0; s < d->nwest; s++) wtext(&w, d->west_st[s]);
    }
    w8(&w, t->nrevoked);
    for (unsigned i = 0; i < t->nrevoked; i++) wb(&w, t->revoked[i], OC_RTBL_KEY);
    return w.bad ? 0 : w.n;
}

/* ---- additions ---- */

static int npa_ok(const char *npa)
{
    char p[8];
    if (strlen(npa) != 3) return 0;
    snprintf(p, sizeof(p), "8831%s", npa);
    return oc_core_route_prefix_ok(p);
}

int oc_rtbl_add_decode(const uint8_t *blob, size_t n, oc_rtbl_add_t *a, char *err, size_t cap)
{
    rd_t r = { blob, n, 0, 0 };
    uint8_t magic[4];
    memset(a, 0, sizeof(*a));
    rb(&r, magic, 4);
    if (r.bad || memcmp(magic, "OCRA", 4) != 0 || r8(&r) != 1) {
        errf(err, cap, "malformed: not an addition (magic OCRA, format 1)");
        return -1;
    }
    a->root_version = r32(&r);
    a->seq = r16(&r);
    a->issued = r32(&r);
    rb(&r, a->delegate, OC_RTBL_KEY);
    a->n = r8(&r);
    if (r.bad || a->seq == 0 || a->n == 0 || a->n > OC_RTBL_ADD_MAX) {
        errf(err, cap, "malformed: seq >= 1, 1-%u blocks", OC_RTBL_ADD_MAX);
        return -1;
    }
    for (unsigned i = 0; i < a->n; i++) {
        oc_rtbl_addblk_t *b = &a->b[i];
        rb(&r, (uint8_t *)b->npa, 3);
        b->npa[3] = '\0';
        b->idx = r16(&r);
        rtext(&r, b->state, OC_CORE_STATE_MAX);
        if (r.bad || !npa_ok(b->npa) || b->idx == 0 || !oc_rtbl_state_ok(b->state)) {
            errf(err, cap, "malformed: block %u", i);
            return -1;
        }
    }
    if (r.at != n) {
        errf(err, cap, "malformed: bytes after the end");
        return -1;
    }
    return 0;
}

size_t oc_rtbl_add_encode(const oc_rtbl_add_t *a, uint8_t *out, size_t cap)
{
    wr_t w = { out, 0, cap, 0 };
    wb(&w, (const uint8_t *)"OCRA", 4);
    w8(&w, 1);
    w32(&w, a->root_version);
    w16(&w, a->seq);
    w32(&w, a->issued);
    wb(&w, a->delegate, OC_RTBL_KEY);
    w8(&w, a->n);
    for (unsigned i = 0; i < a->n && i < OC_RTBL_ADD_MAX; i++) {
        if (strlen(a->b[i].npa) != 3) return 0;
        wb(&w, (const uint8_t *)a->b[i].npa, 3);
        w16(&w, a->b[i].idx);
        wtext(&w, a->b[i].state);
    }
    return w.bad ? 0 : w.n;
}

/* ---- Ed25519 ---- */

int oc_rtbl_verify(const uint8_t pub[OC_RTBL_KEY], const uint8_t *msg, size_t n, const uint8_t sig[OC_RTBL_SIG])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, OC_RTBL_KEY);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = k != NULL && c != NULL && EVP_DigestVerifyInit(c, NULL, NULL, NULL, k) == 1 &&
             EVP_DigestVerify(c, sig, OC_RTBL_SIG, msg, n) == 1;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    return ok;
}

static int sign_with(EVP_PKEY *k, const uint8_t *msg, size_t n, uint8_t sig[OC_RTBL_SIG], uint8_t pub[OC_RTBL_KEY])
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t sl = OC_RTBL_SIG, pl = OC_RTBL_KEY;
    int ok = k != NULL && c != NULL && EVP_PKEY_get_base_id(k) == EVP_PKEY_ED25519 &&
             EVP_DigestSignInit(c, NULL, NULL, NULL, k) == 1 && EVP_DigestSign(c, sig, &sl, msg, n) == 1 &&
             sl == OC_RTBL_SIG && (pub == NULL || (EVP_PKEY_get_raw_public_key(k, pub, &pl) == 1 && pl == OC_RTBL_KEY));
    EVP_MD_CTX_free(c);
    return ok ? 0 : -1;
}

int oc_rtbl_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t n, uint8_t sig[OC_RTBL_SIG],
                      uint8_t pub[OC_RTBL_KEY])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    int r = sign_with(k, msg, n, sig, pub);
    EVP_PKEY_free(k);
    return r;
}

int oc_rtbl_sign_pem(const char *path, const uint8_t *msg, size_t n, uint8_t sig[OC_RTBL_SIG], uint8_t pub[OC_RTBL_KEY])
{
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    int r = sign_with(k, msg, n, sig, pub);
    EVP_PKEY_free(k);
    return r;
}

static void sha256(const uint8_t *b, size_t n, uint8_t out[32])
{
    unsigned int len = 32;
    if (EVP_Digest(b, n, out, &len, EVP_sha256(), NULL) != 1) memset(out, 0, 32);
}

/* ---- the effective table ---- */

static int add_block(oc_rtbl_t *t, const oc_rtbl_block_t *b)
{
    if (oc_core_route_add_ex(&t->route, b->prefix, b->idx, b->home, b->nsec > 0 ? b->sec[0] : 0, b->tenant,
                             b->state) != 0) {
        return -1;
    }
    if (b->idx > t->max_idx) t->max_idx = b->idx;
    return 0;
}

uint32_t oc_rtbl_file_version(const uint8_t *file, size_t n)
{
    if (n < OC_RTBL_SIG + 9u || memcmp(file, "OCRT", 4) != 0 || file[4] != 1) return 0;
    return (uint32_t)file[5] | (uint32_t)file[6] << 8 | (uint32_t)file[7] << 16 | (uint32_t)file[8] << 24;
}

int oc_rtbl_load(oc_rtbl_t *t, uint16_t self, const uint8_t root_pub[OC_RTBL_KEY], const uint8_t *file, size_t n,
                 char *err, size_t cap)
{
    memset(t, 0, sizeof(*t));
    t->self = self;
    if (n <= OC_RTBL_SIG || n > OC_RTBL_ROOT_MAX) {
        errf(err, cap, "not a root table file (size %zu)", n);
        return -1;
    }
    size_t bn = n - OC_RTBL_SIG;
    if (!oc_rtbl_verify(root_pub, file, bn, file + bn)) {
        errf(err, cap, "the root table's signature does not verify with route_root");
        return -1;
    }
    if (oc_rtbl_root_decode(file, bn, &t->root, err, cap) != 0) return -1;
    if (!in_dir(&t->root, self)) {
        errf(err, cap, "this core (%u) is not in the table's directory", self);
        return -1;
    }
    sha256(file, bn, t->root_blob_sha);
    t->max_idx = t->root.max_idx;
    oc_core_route_init(&t->route, self);
    for (unsigned i = 0; i < t->root.nblocks; i++) {
        if (add_block(t, &t->root.blocks[i]) != 0) {
            errf(err, cap, "block %s: refused by the route table", t->root.blocks[i].prefix);
            return -1;
        }
    }
    return 0;
}

static int revoked(const oc_rtbl_root_t *r, const uint8_t pub[OC_RTBL_KEY])
{
    for (unsigned i = 0; i < r->nrevoked; i++) {
        if (memcmp(r->revoked[i], pub, OC_RTBL_KEY) == 0) return 1;
    }
    return 0;
}

static const oc_rtbl_deleg_t *deleg_valid(const oc_rtbl_root_t *r, const uint8_t pub[OC_RTBL_KEY], uint32_t now)
{
    if (revoked(r, pub)) return NULL;
    for (unsigned i = 0; i < r->ndeleg; i++) {
        const oc_rtbl_deleg_t *d = &r->deleg[i];
        if (memcmp(d->pub, pub, OC_RTBL_KEY) == 0 && d->scope == OC_RTBL_SCOPE_ADD_NPA && d->not_before <= now &&
            now <= d->not_after) {
            return d;
        }
    }
    return NULL;
}

uint32_t oc_rtbl_deleg_until(const oc_rtbl_t *t, uint32_t now)
{
    uint32_t until = 0;
    for (unsigned i = 0; i < t->root.ndeleg; i++) {
        const oc_rtbl_deleg_t *d = deleg_valid(&t->root, t->root.deleg[i].pub, now);
        if (d != NULL && d->not_after > until) until = d->not_after;
    }
    return until;
}

static int listed(const char (*list)[OC_CORE_STATE_MAX + 1], unsigned n, const char *s)
{
    for (unsigned i = 0; i < n; i++) {
        if (strcmp(list[i], s) == 0) return 1;
    }
    return 0;
}

int oc_rtbl_offer(const oc_rtbl_t *cur, oc_rtbl_t *next, uint32_t table_version, const uint8_t *blob, size_t n,
                  const uint8_t sig[OC_RTBL_SIG], uint32_t now, int *fresh, char *msg, size_t cap)
{
    oc_rtbl_add_t a;
    uint8_t h[32];
    *fresh = 0;
    if (n == 0 || n > OC_RTBL_BLOB_MAX || oc_rtbl_add_decode(blob, n, &a, msg, cap) != 0) { /* rule 2 */
        if (n == 0 || n > OC_RTBL_BLOB_MAX) errf(msg, cap, "malformed: 1-%u bytes", OC_RTBL_BLOB_MAX);
        return OC_RTBL_INVALID;
    }
    if (a.root_version != table_version || a.root_version != cur->root.version) { /* rule 3 */
        errf(msg, cap, "root version %u expected", (unsigned)cur->root.version);
        return OC_RTBL_INVALID;
    }
    const oc_rtbl_deleg_t *d = deleg_valid(&cur->root, a.delegate, now); /* rule 4 */
    if (d == NULL) {
        errf(msg, cap, "no valid delegation for that key");
        return OC_RTBL_INVALID;
    }
    if (!oc_rtbl_verify(a.delegate, blob, n, sig)) { /* rule 5 */
        errf(msg, cap, "bad signature");
        return OC_RTBL_INVALID;
    }
    sha256(blob, n, h);
    if (a.seq <= cur->seq) { /* rule 6 */
        if (a.seq <= OC_RTBL_SEQ_MAX && memcmp(cur->add_sha[a.seq - 1u], h, 32) == 0) {
            if (next != cur) memcpy(next, cur, sizeof(*next));
            errf(msg, cap, "already held");
            return OC_RTBL_OK;
        }
        errf(msg, cap, "seq %u holds another addition", (unsigned)a.seq);
        return OC_RTBL_TAKEN;
    }
    if (a.seq != cur->seq + 1u || a.seq > OC_RTBL_SEQ_MAX) {
        errf(msg, cap, "out of order: at seq %u", (unsigned)cur->seq);
        return OC_RTBL_INVALID;
    }
    uint16_t floor = cur->max_idx;
    for (unsigned i = 0; i < a.n; i++) { /* rule 7 */
        char p[8];
        snprintf(p, sizeof(p), "8831%s", a.b[i].npa);
        for (unsigned j = 0; j < cur->route.n; j++) {
            if (strcmp(cur->route.b[j].prefix, p) == 0) {
                errf(msg, cap, "rule: %s is a block already", p);
                return OC_RTBL_INVALID;
            }
        }
        for (unsigned j = 0; j < i; j++) {
            if (strcmp(a.b[j].npa, a.b[i].npa) == 0) {
                errf(msg, cap, "rule: %s twice", p);
                return OC_RTBL_INVALID;
            }
        }
        if (a.b[i].idx <= floor) {
            errf(msg, cap, "rule: block index %u must be above %u", (unsigned)a.b[i].idx, (unsigned)floor);
            return OC_RTBL_INVALID;
        }
        floor = a.b[i].idx;
        if (!listed(d->east_st, d->neast, a.b[i].state) && !listed(d->west_st, d->nwest, a.b[i].state)) {
            errf(msg, cap, "rule: state %s is in neither list", a.b[i].state);
            return OC_RTBL_INVALID;
        }
    }
    if (cur->route.n + a.n > OC_CORE_BLOCKS) { /* rule 8 */
        errf(msg, cap, "table full");
        return OC_RTBL_FULL;
    }
    memcpy(next, cur, sizeof(*next));
    for (unsigned i = 0; i < a.n; i++) {
        oc_rtbl_block_t b;
        memset(&b, 0, sizeof(b));
        snprintf(b.prefix, sizeof(b.prefix), "8831%s", a.b[i].npa);
        b.idx = a.b[i].idx;
        b.tenant = d->tenant;
        int east = listed(d->east_st, d->neast, a.b[i].state);
        b.home = east ? d->east : d->west;
        b.nsec = 1;
        b.sec[0] = east ? d->west : d->east;
        b.epoch = 1;
        snprintf(b.state, sizeof(b.state), "%s", a.b[i].state);
        if (add_block(next, &b) != 0) {
            errf(msg, cap, "rule: block %s refused", b.prefix);
            return OC_RTBL_INVALID;
        }
    }
    next->seq = a.seq;
    memcpy(next->add_sha[a.seq - 1u], h, 32);
    *fresh = 1;
    errf(msg, cap, "%u.%u", (unsigned)next->root.version, (unsigned)next->seq);
    return OC_RTBL_OK;
}

void oc_rtbl_hex(const uint8_t *b, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[b[i] >> 4];
        out[2 * i + 1] = hx[b[i] & 15];
    }
    out[2 * n] = '\0';
}

static int nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int oc_rtbl_unhex(const char *s, uint8_t *out, size_t n)
{
    if (strlen(s) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int a = nib(s[2 * i]), b = nib(s[2 * i + 1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (uint8_t)(a << 4 | b);
    }
    return 0;
}
