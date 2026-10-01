#define _GNU_SOURCE
#include "oc_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oc_log.h"
#include "oc_sig_keys.h" /* oc_sig_wipe */
#include "oc_sig_qr.h"

/* ---- the operations' names and default rates (portal spec §7: "a
 * compromised portal can't enumerate or mass-disable quickly") ---- */

static const struct {
    const char *name;
    uint32_t    per_hour, burst;
} OPS[OC_API_OPS] = {
    /* 0: every operation the core does not have (op 0, an unknown op): one
     * bucket, so a flood of them is refused and audited once a minute too */
    [0] = { "unknown", 60, 10 },
    [OC_API_NUM_FREE] = { "num.free", 600, 60 },         [OC_API_NUM_CHECK] = { "num.check", 600, 60 },
    [OC_API_SUB_CREATE] = { "sub.create", 120, 20 },     [OC_API_SUB_REISSUE] = { "sub.reissue", 120, 20 },
    [OC_API_SUB_STATUS] = { "sub.status", 7200, 120 },   [OC_API_SUB_RELEASE] = { "sub.release", 120, 20 },
    [OC_API_SUB_DISABLE] = { "sub.disable", 30, 10 },    [OC_API_SUB_ENABLE] = { "sub.enable", 30, 10 },
    [OC_API_CDR_LIST] = { "cdr.list", 1200, 60 },        [OC_API_CELL_ADD] = { "cell.add", 20, 5 },
    [OC_API_CELL_SET_CERT] = { "cell.set_cert", 20, 5 }, [OC_API_CELL_REVOKE] = { "cell.revoke", 10, 5 },
    [OC_API_CELL_STATUS] = { "cell.status", 1200, 60 },  [OC_API_CORE_STATUS] = { "core.status", 1200, 60 },
    [OC_API_ROUTE_OFFER] = { "route.offer", 10, 2 },
    [OC_API_CELL_RADIO] = { "cell.radio", 1200, 60 },    [OC_API_REG_LIST] = { "reg.list", 600, 30 },
    [OC_API_CDR_RECENT] = { "cdr.recent", 600, 30 },     [OC_API_AUDIT_LIST] = { "audit.list", 600, 30 },
    [OC_API_OCSS_STATUS] = { "ocss.status", 1200, 60 },  [OC_API_CORE_BLOCKS] = { "core.blocks", 120, 10 },
};

const char *oc_api_op_name(unsigned op)
{
    return op > 0 && op < OC_API_OPS ? OPS[op].name : "?";
}

const char *oc_api_status_name(unsigned s)
{
    static const char *const err[] = { "invalid",         "not_found",    "taken",      "not_assignable",
                                       "not_unactivated", "rate_limited", "unavailable", "unsupported" };
    if (s == OC_API_OK) return "ok";
    if (s == OC_API_MORE) return "more";
    return s >= OC_API_INVALID && s <= OC_API_UNSUPPORTED ? err[s - OC_API_INVALID] : "?";
}

/* ---- reading a request ---- */

typedef struct {
    const uint8_t *p;
    size_t         n, off;
    int            err; /* a field ran past the end, or was malformed */
} rd_t;

static const uint8_t *rd_bytes(rd_t *r, size_t n)
{
    if (r->err || r->n - r->off < n) {
        r->err = 1;
        return NULL;
    }
    const uint8_t *p = r->p + r->off;
    r->off += n;
    return p;
}

static uint8_t rd_u8(rd_t *r)
{
    const uint8_t *p = rd_bytes(r, 1);
    return p != NULL ? p[0] : 0;
}

static uint16_t rd_u16(rd_t *r)
{
    const uint8_t *p = rd_bytes(r, 2);
    return p != NULL ? (uint16_t)(p[0] | p[1] << 8) : 0;
}

static uint32_t rd_u32(rd_t *r)
{
    const uint8_t *p = rd_bytes(r, 4);
    return p != NULL ? (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24 : 0;
}

/* Text into out (NUL-terminated): at most cap - 1 bytes, no NUL inside. */
static void rd_text(rd_t *r, char *out, size_t cap)
{
    uint8_t len = rd_u8(r);
    const uint8_t *p = rd_bytes(r, len);
    out[0] = '\0';
    if (p == NULL || len >= cap || memchr(p, '\0', len) != NULL) {
        r->err = 1;
        return;
    }
    memcpy(out, p, len);
    out[len] = '\0';
}

/* The whole body was read, and nothing was malformed. */
static int rd_done(const rd_t *r) { return !r->err && r->off == r->n; }

/* ---- writing an answer ---- */

typedef struct {
    uint8_t  b[OC_API_FRAME_MAX];
    size_t   n;
    int      err; /* a field did not fit */
    oc_buf_t *out;
    uint8_t  op;
    uint32_t req;
    size_t   count_at; /* a list's row count, or 0 */
    uint8_t  count;
} wr_t;

static void wr_bytes(wr_t *w, const void *p, size_t n)
{
    if (w->err || sizeof(w->b) - w->n < n) {
        w->err = 1;
        return;
    }
    memcpy(w->b + w->n, p, n);
    w->n += n;
}

static void wr_u8(wr_t *w, uint8_t v) { wr_bytes(w, &v, 1); }
static void wr_u16(wr_t *w, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    wr_bytes(w, b, 2);
}
static void wr_u32(wr_t *w, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    wr_bytes(w, b, 4);
}
static void wr_text(wr_t *w, const char *s)
{
    size_t n = strlen(s);
    if (n > 255) n = 255;
    wr_u8(w, (uint8_t)n);
    wr_bytes(w, s, n);
}

/* A frame's head: len (filled in by wr_end), type, req, status. */
static void wr_start(wr_t *w, uint8_t status)
{
    w->n = 0;
    w->err = 0;
    w->count_at = 0;
    w->count = 0;
    wr_u16(w, 0);
    wr_u8(w, (uint8_t)(OC_API_ANSWER | w->op));
    wr_u32(w, w->req);
    wr_u8(w, status);
}

static void wr_end(wr_t *w)
{
    size_t len = w->n - 2u;
    w->b[0] = (uint8_t)(len >> 8);
    w->b[1] = (uint8_t)len;
    if (w->count_at != 0) w->b[w->count_at] = w->count;
    oc_buf_add(w->out, w->b, w->n);
    oc_sig_wipe(w->b, sizeof(w->b)); /* a QR code, for one */
}

/* A list answer: rows go into frames of their own, each but the last
 * marked MORE. */
static void list_start(wr_t *w)
{
    wr_start(w, OC_API_OK);
    w->count_at = w->n;
    wr_u8(w, 0);
}

static void list_row(wr_t *w, const uint8_t *row, size_t n)
{
    if (w->n + n > sizeof(w->b)) {
        w->b[6u + 1u] = OC_API_MORE; /* len 2, type 1, req 4: the status */
        wr_end(w);
        list_start(w);
    }
    wr_bytes(w, row, n);
    w->count++;
}

/* ---- helpers ---- */

static oc_core_store_t store(oc_api_t *a) { return oc_sql_store(a->sql); }

static sqlite3_stmt *q(oc_api_t *a, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(oc_sql_db(a->sql), sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return NULL;
    }
    return st;
}

static int bind_num(sqlite3_stmt *st, int idx, const uint8_t n[OC_SIG_NUMBER_LEN])
{
    char t[OC_SIG_NUMBER_TEXT];
    oc_sig_number_to_text(n, t);
    return st != NULL ? sqlite3_bind_text(st, idx, t, -1, SQLITE_TRANSIENT) : SQLITE_ERROR;
}

static int num_col(sqlite3_stmt *st, int col, uint8_t out[OC_SIG_NUMBER_LEN])
{
    const char *t = (const char *)sqlite3_column_text(st, col);
    memset(out, 0, OC_SIG_NUMBER_LEN);
    return t != NULL && oc_sig_number_to_bcd(t, strlen(t), out) == 0 ? 0 : -1;
}

/* One integer from a query with the number bound as ?1: 0 with *v, 1 no
 * row (or NULL), -1 the store failed. */
static int one_int(oc_api_t *a, const char *sql, const uint8_t n[OC_SIG_NUMBER_LEN], long long *v)
{
    sqlite3_stmt *st = q(a, sql);
    int rc = n != NULL ? bind_num(st, 1, n) : (st != NULL ? SQLITE_OK : SQLITE_ERROR);
    int ret = -1;
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
            *v = sqlite3_column_int64(st, 0);
            ret = 0;
        } else if (rc == SQLITE_ROW || rc == SQLITE_DONE) {
            ret = 1;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int home(oc_api_t *a, const uint8_t n[OC_SIG_NUMBER_LEN])
{
    return oc_core_route_home(a->route, oc_core_route_find(a->route, n));
}

/* The subscriber's state: 0 (s filled, K and OPc wiped), NONE or FAILED. */
static int sub_get(oc_api_t *a, const uint8_t n[OC_SIG_NUMBER_LEN], oc_core_sub_t *s)
{
    oc_core_store_t st = store(a);
    memset(s, 0, sizeof(*s));
    int got = st.sub_get(st.ctx, n, s);
    oc_sig_wipe(s->k, sizeof(s->k));
    oc_sig_wipe(s->opc, sizeof(s->opc));
    return got;
}

static uint8_t core_err(int e)
{
    switch (e) {
    case OC_CORE_E_INVALID: return OC_API_INVALID;
    case OC_CORE_E_NOT_ASSIGNABLE: return OC_API_NOT_ASSIGNABLE;
    case OC_CORE_E_TAKEN: return OC_API_TAKEN;
    case OC_CORE_E_NOT_FOUND: return OC_API_NOT_FOUND;
    case OC_CORE_E_ACTIVATED: return OC_API_NOT_UNACTIVATED;
    default: return OC_API_UNAVAILABLE;
    }
}

/* ---- sub.release_expired (network-core spec §18.3) ---- */

int oc_api_release_expired(oc_api_t *a, const uint8_t *number)
{
    uint8_t list[64][OC_SIG_NUMBER_LEN];
    int total = 0;
    uint32_t now = a->unix_now();
    if (number != NULL) {
        sqlite3_stmt *st = q(a, "SELECT 1 FROM token t JOIN subscriber s ON s.number = t.number"
                                " WHERE t.number = ?1 AND t.used_at = 0 AND s.activated = 0 AND t.expiry <= ?2");
        int rc = bind_num(st, 1, number);
        if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 2, now);
        if (rc == SQLITE_OK) rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_DONE) return 0;
        if (rc != SQLITE_ROW) return -1;
        return oc_core_sub_release(a->core, number, "expired") == 0 ? 1 : -1;
    }
    for (int round = 0; round < 4; round++) {
        int n = oc_sql_expired(a->sql, now, list, 64);
        if (n < 0) return -1;
        for (int i = 0; i < n; i++) {
            if (oc_core_sub_release(a->core, list[i], "expired") != 0) return -1;
            total++;
        }
        if (n < 64) break;
    }
    return total;
}

/* ---- the operations: each reads its fields from r, answers into w (its
 * head written by the caller for OK), and returns the status (anything
 * but OK: the caller answers that status instead, with msg) ---- */

typedef struct {
    oc_api_t   *a;
    rd_t        r;
    wr_t        w;
    const char *msg; /* why, for a status other than OK */
} call_t;

static uint8_t fail(call_t *c, uint8_t status, const char *msg)
{
    c->msg = msg;
    return status;
}

/* A number field: 0, or INVALID (not a full number). The audit record
 * gets it. */
static int number_field(call_t *c, uint8_t n[OC_SIG_NUMBER_LEN])
{
    const uint8_t *p = rd_bytes(&c->r, OC_SIG_NUMBER_LEN);
    if (p == NULL) return -1;
    memcpy(n, p, OC_SIG_NUMBER_LEN);
    if (!oc_sig_number_valid(n)) return -1;
    memcpy(c->a->audit_number, n, OC_SIG_NUMBER_LEN);
    return 0;
}

/* The exchange as text ("8831717464") into its first station number
 * (+883 1 717 464 00000) when it is a NANP exchange: 0 or -1. */
static int exchange_field(const char *ex, char digits[16])
{
    if (strlen(ex) != 10 || strncmp(ex, "8831", 4) != 0) return -1;
    for (int i = 0; i < 10; i++) {
        if (ex[i] < '0' || ex[i] > '9') return -1;
    }
    memcpy(digits, ex, 10);
    memcpy(digits + 10, "00000", 6);
    uint8_t n[OC_SIG_NUMBER_LEN];
    return oc_sig_number_to_bcd(digits, 15, n) == 0 && oc_sig_number_valid(n) ? 0 : -1;
}

static uint8_t op_num_free(call_t *c)
{
    char ex[16], pattern[8], d[16];
    rd_text(&c->r, ex, sizeof(ex));
    uint8_t count = rd_u8(&c->r);
    rd_text(&c->r, pattern, sizeof(pattern));
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    snprintf(c->a->audit_what, sizeof(c->a->audit_what), "%.10s %u%s%.5s", ex, count, pattern[0] != '\0' ? " " : "",
             pattern);
    if (exchange_field(ex, d) != 0) return fail(c, OC_API_INVALID, "the exchange is 8831 NPA NXX");
    if (count < 1 || count > OC_API_FREE_MAX) return fail(c, OC_API_INVALID, "count is 1-32");
    size_t pl = strlen(pattern);
    if (pl != 0 && (pl != 5 || strspn(pattern, "0123456789x") != 5)) {
        return fail(c, OC_API_INVALID, "pattern is 5 of [0-9x]");
    }
    uint8_t first[OC_SIG_NUMBER_LEN];
    oc_sig_number_to_bcd(d, 15, first);
    const oc_core_block_t *b = oc_core_route_find(c->a->route, first);
    if (!oc_core_route_home(c->a->route, b)) return fail(c, OC_API_NOT_ASSIGNABLE, "not an exchange this core serves");
    uint8_t got[OC_API_FREE_MAX][OC_SIG_NUMBER_LEN];
    unsigned n = 0;
    for (unsigned tries = 0; n < count && tries < 20u * count; tries++) {
        uint8_t r[4], num[OC_SIG_NUMBER_LEN];
        c->a->core->io.random(c->a->core->io.ctx, r, sizeof(r));
        unsigned station = 1000u + ((unsigned)r[0] << 16 | (unsigned)r[1] << 8 | r[2]) % 98999u;
        for (int i = 14; i >= 10; i--, station /= 10u) d[i] = (char)('0' + station % 10u);
        for (int i = 0; pl == 5 && i < 5; i++) {
            if (pattern[i] != 'x') d[10 + i] = pattern[i];
        }
        if (oc_sig_number_to_bcd(d, 15, num) != 0 || oc_core_number_reserved(num)) continue;
        if (oc_core_route_find(c->a->route, num) != b) continue; /* a longer block inside: not this one's */
        int dup = 0;
        for (unsigned i = 0; i < n && !dup; i++) dup = memcmp(got[i], num, OC_SIG_NUMBER_LEN) == 0;
        if (dup) continue;
        oc_core_sub_t s;
        int g = sub_get(c->a, num, &s);
        if (g == OC_CORE_STORE_FAILED) return fail(c, OC_API_UNAVAILABLE, "store error");
        if (g == OC_CORE_STORE_NONE) memcpy(got[n++], num, OC_SIG_NUMBER_LEN);
    }
    wr_u8(&c->w, (uint8_t)n);
    for (unsigned i = 0; i < n; i++) wr_bytes(&c->w, got[i], OC_SIG_NUMBER_LEN);
    return OC_API_OK;
}

static uint8_t op_num_check(call_t *c)
{
    uint8_t n[OC_SIG_NUMBER_LEN], result = 2;
    const uint8_t *p = rd_bytes(&c->r, OC_SIG_NUMBER_LEN);
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    memcpy(n, p, OC_SIG_NUMBER_LEN);
    if (oc_sig_number_valid(n)) {
        memcpy(c->a->audit_number, n, OC_SIG_NUMBER_LEN);
        if (!oc_core_number_reserved(n) && home(c->a, n)) {
            if (oc_api_release_expired(c->a, n) < 0) return fail(c, OC_API_UNAVAILABLE, "store error");
            oc_core_sub_t s;
            int g = sub_get(c->a, n, &s);
            if (g == OC_CORE_STORE_FAILED) return fail(c, OC_API_UNAVAILABLE, "store error");
            result = g == 0 ? 1 : 0;
        }
    }
    wr_u8(&c->w, result);
    return OC_API_OK;
}

/* sub.create and sub.reissue: the QR text of the token just issued. */
static void answer_qr(call_t *c, const oc_sig_qr_t *qr)
{
    char text[OC_SIG_QR_TEXT + 1];
    size_t len = oc_sig_qr_format(qr, text, sizeof(text));
    wr_bytes(&c->w, qr->number, OC_SIG_NUMBER_LEN);
    wr_u32(&c->w, qr->expiry);
    wr_text(&c->w, len > 0 ? text : "");
    oc_sig_wipe(text, sizeof(text));
}

static uint8_t op_sub_create(call_t *c, int reissue)
{
    uint8_t n[OC_SIG_NUMBER_LEN];
    oc_sig_qr_t qr;
    if (number_field(c, n) != 0 || !rd_done(&c->r)) return fail(c, OC_API_INVALID, "not a full number");
    if (oc_api_release_expired(c->a, n) < 0) return fail(c, OC_API_UNAVAILABLE, "store error");
    int e;
    if (!reissue) {
        e = oc_core_sub_create(c->a->core, n, OC_API_TOKEN_S, &qr);
    } else {
        oc_core_sub_t s;
        int g = sub_get(c->a, n, &s);
        if (g == OC_CORE_STORE_NONE) return fail(c, OC_API_NOT_FOUND, "not a subscriber");
        if (g != 0) return fail(c, OC_API_UNAVAILABLE, "store error");
        if (s.state != OC_CORE_SUB_ACTIVE) return fail(c, OC_API_INVALID, "disabled");
        e = oc_core_token_issue(c->a->core, n, OC_API_TOKEN_S, &qr) == 0 ? 0 : OC_CORE_E_STORE;
    }
    if (e != 0) return fail(c, core_err(e), e == OC_CORE_E_STORE ? "store error" : "refused");
    answer_qr(c, &qr);
    oc_sig_wipe(&qr, sizeof(qr));
    return c->w.err ? fail(c, OC_API_UNAVAILABLE, "answer too long") : OC_API_OK;
}

/* When the core last heard of the number's terminal (unix s, 0 never): its
 * live location's last refresh, its newest proven vector (kept 24 h), or
 * its last ACTIVATE or REGISTER record, whichever is newest. -1: the store
 * failed. */
static long long last_seen(oc_api_t *a, const uint8_t n[OC_SIG_NUMBER_LEN])
{
    char sql[512];
    long long v = 0;
    snprintf(sql, sizeof(sql),
             "SELECT max(t) FROM ("
             " SELECT l.expires - 2 * coalesce((SELECT period_s FROM network WHERE key_id = %u), 1800) AS t"
             "  FROM location l WHERE l.number = ?1"
             " UNION ALL SELECT max(issued) FROM av_issued WHERE number = ?1 AND confirmed = 1"
             " UNION ALL SELECT max(ts) FROM audit WHERE number = ?1 AND event IN (%d, %d))",
             (unsigned)a->cfg->key_id, OC_CORE_AUDIT_ACTIVATE, OC_CORE_AUDIT_REGISTER);
    int got = one_int(a, sql, n, &v);
    return got < 0 ? -1 : got == 1 || v < 0 ? 0 : v;
}

static uint8_t op_sub_status(call_t *c)
{
    uint8_t n[OC_SIG_NUMBER_LEN];
    oc_core_sub_t s;
    if (number_field(c, n) != 0 || !rd_done(&c->r)) return fail(c, OC_API_INVALID, "not a full number");
    if (oc_api_release_expired(c->a, n) < 0) return fail(c, OC_API_UNAVAILABLE, "store error");
    int g = sub_get(c->a, n, &s);
    if (g == OC_CORE_STORE_NONE) return fail(c, OC_API_NOT_FOUND, "not a subscriber");
    if (g != 0) return fail(c, OC_API_UNAVAILABLE, "store error");
    long long expiry = 0, cell = 0, expires = 0;
    int ge = s.activated ? 1 : one_int(c->a, "SELECT expiry FROM token WHERE number = ?1 AND used_at = 0", n, &expiry);
    int gc = one_int(c->a, "SELECT cell_id FROM location WHERE number = ?1", n, &cell);
    int gx = one_int(c->a, "SELECT expires FROM location WHERE number = ?1", n, &expires);
    long long seen = last_seen(c->a, n);
    if (ge < 0 || gc < 0 || gx < 0 || seen < 0) return fail(c, OC_API_UNAVAILABLE, "store error");
    int registered = gx == 0 && expires > (long long)c->a->unix_now();
    wr_bytes(&c->w, n, OC_SIG_NUMBER_LEN);
    wr_u8(&c->w, s.activated ? 1 : 0);
    wr_u8(&c->w, s.state == OC_CORE_SUB_DISABLED ? 1 : 0);
    wr_u32(&c->w, ge == 0 ? (uint32_t)expiry : 0);
    wr_u8(&c->w, (uint8_t)registered);
    wr_u32(&c->w, registered ? (uint32_t)cell : 0);
    wr_u16(&c->w, s.activated ? (uint16_t)(s.tmid >> 16) : 0);
    wr_u32(&c->w, (uint32_t)seen);
    return OC_API_OK;
}

static uint8_t op_sub_change(call_t *c, uint8_t op, uint32_t actor)
{
    uint8_t n[OC_SIG_NUMBER_LEN];
    oc_core_sub_t s;
    if (number_field(c, n) != 0 || !rd_done(&c->r)) return fail(c, OC_API_INVALID, "not a full number");
    if (oc_api_release_expired(c->a, n) < 0) return fail(c, OC_API_UNAVAILABLE, "store error");
    int e;
    if (op == OC_API_SUB_RELEASE) {
        char why[16];
        snprintf(why, sizeof(why), "a%u", (unsigned)actor);
        e = oc_core_sub_release(c->a->core, n, why);
        if (e == OC_CORE_E_NOT_FOUND) { /* idempotent: free already (the 72 h job, an earlier call) */
            snprintf(c->a->audit_what, sizeof(c->a->audit_what), "free already");
            e = 0;
        }
    } else if (op == OC_API_SUB_ENABLE) {
        e = oc_core_sub_enable(c->a->core, n);
    } else {
        int g = sub_get(c->a, n, &s);
        if (g == OC_CORE_STORE_NONE) return fail(c, OC_API_NOT_FOUND, "not a subscriber");
        if (g != 0) return fail(c, OC_API_UNAVAILABLE, "store error");
        e = 0;
        if (s.state != OC_CORE_SUB_DISABLED && oc_core_sub_disable(c->a->core, n, c->a->now_us()) != 0) {
            e = OC_CORE_E_STORE;
        }
    }
    if (e != 0) return fail(c, core_err(e), e == OC_CORE_E_STORE ? "store error" : "refused");
    return OC_API_OK;
}

static uint8_t op_cdr_list(call_t *c)
{
    uint8_t n[OC_SIG_NUMBER_LEN];
    if (number_field(c, n) != 0) return fail(c, OC_API_INVALID, "not a full number");
    uint32_t since = rd_u32(&c->r);
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    snprintf(c->a->audit_what, sizeof(c->a->audit_what), "since %u", (unsigned)since);
    sqlite3_stmt *st = q(c->a, "SELECT setup, answer, \"end\", cause, caller = ?1, caller, called FROM cdr"
                               " WHERE (caller = ?1 OR called = ?1) AND setup >= ?2 ORDER BY setup DESC, id DESC"
                               " LIMIT ?3");
    int rc = bind_num(st, 1, n);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 2, since);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int(st, 3, (int)OC_API_CDR_MAX);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(st);
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    list_start(&c->w);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        wr_t row = { .n = 0 };
        uint8_t peer[OC_SIG_NUMBER_LEN];
        int out = sqlite3_column_int(st, 4);
        if (num_col(st, out ? 6 : 5, peer) != 0) continue; /* a row oc_core never wrote */
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 0));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 1));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 2));
        wr_u8(&row, (uint8_t)sqlite3_column_int(st, 3));
        wr_u8(&row, out ? 0 : 1);
        wr_bytes(&row, peer, OC_SIG_NUMBER_LEN);
        list_row(&c->w, row.b, row.n);
    }
    sqlite3_finalize(st);
    /* frames already queued (MORE) stay: the portal drops a list that ends in an error */
    if (rc != SQLITE_DONE) return fail(c, OC_API_UNAVAILABLE, "store error");
    return OC_API_OK;
}

static uint8_t op_cell_add(call_t *c)
{
    char name[32];
    rd_text(&c->r, name, sizeof(name));
    uint8_t mode = rd_u8(&c->r);
    uint16_t group = rd_u16(&c->r);
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    snprintf(c->a->audit_what, sizeof(c->a->audit_what), "%s", name);
    char clean[32];
    snprintf(clean, sizeof(clean), "%s", name);
    if (name[0] == '\0' || oc_log_clean(clean)) return fail(c, OC_API_INVALID, "name: 1-31 printable characters");
    if (mode != 1 && mode != 2) return fail(c, OC_API_INVALID, "mode: 1 part15, 2 part97");
    long long next = 0;
    if (one_int(c->a, "SELECT coalesce(max(cell_id), 0) + 1 FROM cell", NULL, &next) != 0 || next > 0xFFFFFFFFll) {
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    int r = oc_core_cell_add(c->a->core, (uint32_t)next, name, mode == 2 ? OC_SIG_MODE_PART97 : OC_SIG_MODE_PART15,
                             group);
    if (r != 0) return fail(c, OC_API_UNAVAILABLE, "store error");
    c->a->audit_cell = (uint32_t)next;
    wr_u32(&c->w, (uint32_t)next);
    return OC_API_OK;
}

static uint8_t op_cell_change(call_t *c, uint8_t op)
{
    uint32_t id = rd_u32(&c->r);
    const uint8_t *fpr = op == OC_API_CELL_SET_CERT ? rd_bytes(&c->r, 32) : NULL;
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    c->a->audit_cell = id;
    oc_core_store_t st = store(c->a);
    oc_core_cell_t cell;
    int g = id == 0 ? OC_CORE_STORE_NONE : st.cell_get(st.ctx, id, &cell);
    if (g == OC_CORE_STORE_NONE) return fail(c, OC_API_NOT_FOUND, "no such cell");
    if (g != 0) return fail(c, OC_API_UNAVAILABLE, "store error");
    if (op == OC_API_CELL_SET_CERT) {
        char hex[65];
        for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", fpr[i]);
        snprintf(c->a->audit_what, sizeof(c->a->audit_what), "%.16s", hex);
        if (!cell.enabled) return fail(c, OC_API_INVALID, "revoked");
        return oc_sql_cell_cert_set(c->a->sql, id, hex) == 0 ? OC_API_OK : fail(c, OC_API_UNAVAILABLE, "store error");
    }
    if (cell.enabled && oc_core_cell_revoke(c->a->core, id, c->a->now_us()) != 0) {
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    /* unpinned even when it was revoked already: a revoke may have stopped between the two */
    return oc_sql_cell_cert_set(c->a->sql, id, NULL) == 0 ? OC_API_OK : fail(c, OC_API_UNAVAILABLE, "store error");
}

static int linked(oc_api_t *a, uint32_t cell_id)
{
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (a->core->links[i].used && a->core->links[i].cell_id == cell_id) return 1;
    }
    return 0;
}

static uint16_t calls_on(oc_api_t *a, uint32_t cell_id)
{
    uint16_t n = 0;
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        const oc_core_call_t *k = &a->core->calls[i];
        n += k->used && (k->a.cell == cell_id || k->b.cell == cell_id);
    }
    return n;
}

static uint8_t op_cell_status(call_t *c)
{
    uint32_t id = rd_u32(&c->r);
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    c->a->audit_cell = id;
    sqlite3_stmt *st = q(c->a, "SELECT cell_id, enabled, mode, list_id, cert_fpr, last_seen, name,"
                               " (SELECT count(*) FROM location l WHERE l.cell_id = cell.cell_id AND l.expires > ?2)"
                               " FROM cell WHERE ?1 = 0 OR cell_id = ?1 ORDER BY cell_id LIMIT 1000");
    int rc = st != NULL ? sqlite3_bind_int64(st, 1, id) : SQLITE_ERROR;
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 2, c->a->unix_now());
    if (rc != SQLITE_OK) {
        sqlite3_finalize(st);
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    unsigned rows = 0;
    list_start(&c->w);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        wr_t row = { .n = 0 };
        uint8_t fpr[32];
        char name[32];
        uint32_t cid = (uint32_t)sqlite3_column_int64(st, 0);
        const char *hex = (const char *)sqlite3_column_text(st, 4);
        int pinned = hex != NULL && strlen(hex) == 64;
        memset(fpr, 0, sizeof(fpr));
        for (int i = 0; pinned && i < 32; i++) {
            unsigned v;
            if (sscanf(hex + 2 * i, "%2x", &v) != 1) pinned = 0;
            fpr[i] = (uint8_t)v;
        }
        if (!pinned) memset(fpr, 0, sizeof(fpr));
        long long terms = sqlite3_column_int64(st, 7);
        snprintf(name, sizeof(name), "%s", sqlite3_column_text(st, 6) != NULL ? (const char *)sqlite3_column_text(st, 6) : "");
        wr_u32(&row, cid);
        wr_u8(&row, (uint8_t)sqlite3_column_int(st, 1));
        wr_u8(&row, sqlite3_column_int(st, 2) == OC_SIG_MODE_PART97 ? 2 : 1);
        wr_u16(&row, (uint16_t)sqlite3_column_int(st, 3));
        wr_u8(&row, (uint8_t)pinned);
        wr_bytes(&row, fpr, 32);
        wr_u8(&row, (uint8_t)linked(c->a, cid));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 5));
        wr_u16(&row, terms > 65535 ? 65535 : (uint16_t)terms);
        wr_u16(&row, calls_on(c->a, cid));
        wr_text(&row, name);
        list_row(&c->w, row.b, row.n);
        rows++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(c, OC_API_UNAVAILABLE, "store error");
    if (id != 0 && rows == 0) return fail(c, OC_API_NOT_FOUND, "no such cell");
    return OC_API_OK;
}

/* A cell named in a request exists: OK, NOT_FOUND or UNAVAILABLE (0: every cell). */
static uint8_t cell_known(call_t *c, uint32_t id)
{
    if (id == 0) return OC_API_OK;
    oc_core_store_t st = store(c->a);
    oc_core_cell_t cell;
    int g = st.cell_get(st.ctx, id, &cell);
    if (g == OC_CORE_STORE_NONE) return fail(c, OC_API_NOT_FOUND, "no such cell");
    return g == 0 ? OC_API_OK : fail(c, OC_API_UNAVAILABLE, "store error");
}

static uint8_t op_cell_radio(call_t *c)
{
    uint32_t id = rd_u32(&c->r);
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    c->a->audit_cell = id;
    uint8_t known = cell_known(c, id);
    if (known != OC_API_OK) return known;
    list_start(&c->w);
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        const oc_core_link_t *l = &c->a->core->links[i];
        if (!l->used || l->cell_id == 0 || (id != 0 && l->cell_id != id)) continue;
        const oc_core_tel_t *t = oc_core_cell_tel(c->a->core, l->cell_id);
        for (uint8_t k = 0; t != NULL && k < t->nradio; k++) {
            const oc_core_radio_t *x = &t->radio[k];
            wr_t row = { .n = 0 };
            wr_u32(&row, l->cell_id);
            wr_u8(&row, x->radio);
            wr_u8(&row, x->role);
            wr_u8(&row, x->band);
            wr_bytes(&row, x->fw, 3);
            wr_u8(&row, x->anchor);
            wr_u8(&row, x->pps);
            wr_u8(&row, x->timebase);
            wr_u8(&row, (uint8_t)x->temp_c);
            wr_u32(&row, x->uptime_s);
            wr_u32(&row, t->at);
            wr_u32(&row, x->schedules);
            wr_u32(&row, x->rach);
            wr_u32(&row, x->attach);
            wr_u32(&row, x->grants);
            wr_u32(&row, x->ack_err);
            wr_u32(&row, x->ack_late);
            wr_u16(&row, x->late_slots);
            wr_u16(&row, x->radio_errors);
            wr_u16(&row, (uint16_t)x->last_radio_err);
            wr_u16(&row, x->sched_misses);
            wr_u16(&row, x->uart_crc);
            wr_u8(&row, t->nterm);
            list_row(&c->w, row.b, row.n);
        }
    }
    return OC_API_OK;
}

/* A terminal's signal from its cell's latest report: RSSI, SNR, heard at. */
static void signal_of(const oc_api_t *a, uint32_t cell_id, uint32_t tmid, int16_t *rssi, int16_t *snr, uint32_t *heard)
{
    const oc_core_tel_t *t = oc_core_cell_tel(a->core, cell_id);
    *rssi = *snr = OC_CORE_STATUS_NONE;
    *heard = 0;
    for (uint8_t i = 0; t != NULL && i < t->nterm; i++) {
        const oc_core_term_sig_t *s = &t->term[i];
        if (s->tmid != tmid || s->rssi_dbm == OC_CORE_STATUS_NONE) continue;
        *rssi = s->rssi_dbm;
        *snr = s->snr_qdb;
        *heard = s->heard_age_s == 65535u || s->heard_age_s > t->at ? 0 : t->at - s->heard_age_s;
        return;
    }
}

static uint8_t op_reg_list(call_t *c)
{
    static const uint8_t none[OC_SIG_NUMBER_LEN];
    uint32_t id = rd_u32(&c->r);
    const uint8_t *after = rd_bytes(&c->r, OC_SIG_NUMBER_LEN);
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    int from_start = memcmp(after, none, sizeof(none)) == 0;
    if (!from_start && !oc_sig_number_valid(after)) return fail(c, OC_API_INVALID, "after: not a full number");
    c->a->audit_cell = id;
    uint8_t known = cell_known(c, id);
    if (known != OC_API_OK) return known;
    char after_text[OC_SIG_NUMBER_TEXT] = "";
    if (!from_start) oc_sig_number_to_text(after, after_text);
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT l.number, l.tmid, l.cell_id, l.expires,"
             " (SELECT max(a.ts) FROM audit a WHERE a.number = l.number AND a.event = %d)"
             " FROM location l WHERE l.expires > ?1 AND (?2 = 0 OR l.cell_id = ?2) AND l.number > ?3"
             " ORDER BY l.number LIMIT %u",
             OC_CORE_AUDIT_REGISTER, OC_API_REG_MAX);
    sqlite3_stmt *st = q(c->a, sql);
    int rc = st != NULL ? sqlite3_bind_int64(st, 1, c->a->unix_now()) : SQLITE_ERROR;
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 2, id);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(st, 3, after_text, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(st);
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    list_start(&c->w);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint8_t n[OC_SIG_NUMBER_LEN];
        if (num_col(st, 0, n) != 0) continue; /* a row oc_core never wrote */
        uint32_t tmid = (uint32_t)sqlite3_column_int64(st, 1), cell = (uint32_t)sqlite3_column_int64(st, 2);
        int16_t rssi, snr;
        uint32_t heard;
        signal_of(c->a, cell, tmid, &rssi, &snr, &heard);
        wr_t row = { .n = 0 };
        wr_bytes(&row, n, OC_SIG_NUMBER_LEN);
        wr_u16(&row, (uint16_t)(tmid >> 16));
        wr_u32(&row, cell);
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 4));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 3));
        wr_u16(&row, (uint16_t)rssi);
        wr_u16(&row, (uint16_t)snr);
        wr_u32(&row, heard);
        list_row(&c->w, row.b, row.n);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(c, OC_API_UNAVAILABLE, "store error");
    return OC_API_OK;
}

/* A CDR leg's kind (NOC design §7.1): a cell's, or else, for the called
 * side, the echo or the playback service, and otherwise a peer core's. */
static uint8_t leg_kind(const oc_api_t *a, uint32_t cell, const uint8_t *number, int called)
{
    if (cell != 0) return 0;
    if (called && memcmp(number, a->cfg->echo_number, OC_SIG_NUMBER_LEN) == 0) return 1;
    if (called && memcmp(number, a->cfg->playback_number, OC_SIG_NUMBER_LEN) == 0) return 2;
    return 3;
}

static uint8_t op_cdr_recent(call_t *c)
{
    uint32_t after = rd_u32(&c->r);
    uint16_t limit = rd_u16(&c->r);
    if (!rd_done(&c->r) || limit < 1 || limit > OC_API_CDR_MAX) return fail(c, OC_API_INVALID, "after (4), limit 1-1000");
    snprintf(c->a->audit_what, sizeof(c->a->audit_what), "after %u", (unsigned)after);
    sqlite3_stmt *st = q(c->a, "SELECT id, setup, answer, \"end\", cause, caller, called, cell_a, cell_b FROM cdr"
                               " WHERE id > ?1 ORDER BY id LIMIT ?2");
    int rc = st != NULL ? sqlite3_bind_int64(st, 1, after) : SQLITE_ERROR;
    if (rc == SQLITE_OK) rc = sqlite3_bind_int(st, 2, limit);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(st);
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    list_start(&c->w);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint8_t caller[OC_SIG_NUMBER_LEN], called[OC_SIG_NUMBER_LEN];
        if (num_col(st, 5, caller) != 0 || num_col(st, 6, called) != 0) continue; /* a row oc_core never wrote */
        uint32_t cell_a = (uint32_t)sqlite3_column_int64(st, 7), cell_b = (uint32_t)sqlite3_column_int64(st, 8);
        wr_t row = { .n = 0 };
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 0));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 1));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 2));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 3));
        wr_u8(&row, (uint8_t)sqlite3_column_int(st, 4));
        wr_bytes(&row, caller, OC_SIG_NUMBER_LEN);
        wr_bytes(&row, called, OC_SIG_NUMBER_LEN);
        wr_u32(&row, cell_a);
        wr_u32(&row, cell_b);
        wr_u8(&row, (uint8_t)(leg_kind(c->a, cell_a, caller, 0) << 4 | leg_kind(c->a, cell_b, called, 1)));
        list_row(&c->w, row.b, row.n);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(c, OC_API_UNAVAILABLE, "store error");
    return OC_API_OK;
}

static uint8_t op_audit_list(call_t *c)
{
    static const uint8_t none[OC_SIG_NUMBER_LEN];
    uint32_t after = rd_u32(&c->r), mask = rd_u32(&c->r);
    const uint8_t *nb = rd_bytes(&c->r, OC_SIG_NUMBER_LEN);
    uint16_t limit = rd_u16(&c->r);
    if (!rd_done(&c->r) || limit < 1 || limit > OC_API_AUDIT_MAX) {
        return fail(c, OC_API_INVALID, "after (4), mask (4), number, limit 1-500");
    }
    int any = memcmp(nb, none, sizeof(none)) == 0;
    if (!any && !oc_sig_number_valid(nb)) return fail(c, OC_API_INVALID, "not a full number");
    if (!any) memcpy(c->a->audit_number, nb, OC_SIG_NUMBER_LEN); /* who was looked at, in this call's own record */
    snprintf(c->a->audit_what, sizeof(c->a->audit_what), "after %u", (unsigned)after);
    sqlite3_stmt *st = q(c->a, "SELECT id, ts, event, number, tmid, cell_id, detail FROM audit"
                               " WHERE id > ?1 AND (?2 = 0 OR (event < 32 AND (?2 >> event) & 1))"
                               " AND (?3 = '' OR number = ?3) ORDER BY id LIMIT ?4");
    char nt[OC_SIG_NUMBER_TEXT] = "";
    if (!any) oc_sig_number_to_text(nb, nt);
    int rc = st != NULL ? sqlite3_bind_int64(st, 1, after) : SQLITE_ERROR;
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 2, mask);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(st, 3, nt, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int(st, 4, limit);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(st);
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    list_start(&c->w);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint8_t n[OC_SIG_NUMBER_LEN];
        if (sqlite3_column_type(st, 3) == SQLITE_NULL || num_col(st, 3, n) != 0) memset(n, 0, sizeof(n));
        char detail[64];
        snprintf(detail, sizeof(detail), "%s", sqlite3_column_text(st, 6) != NULL ? (const char *)sqlite3_column_text(st, 6) : "");
        wr_t row = { .n = 0 };
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 0));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 1));
        wr_u8(&row, (uint8_t)sqlite3_column_int(st, 2));
        wr_bytes(&row, n, OC_SIG_NUMBER_LEN);
        wr_u16(&row, (uint16_t)((uint32_t)sqlite3_column_int64(st, 4) >> 16));
        wr_u32(&row, (uint32_t)sqlite3_column_int64(st, 5));
        wr_text(&row, detail);
        list_row(&c->w, row.b, row.n);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(c, OC_API_UNAVAILABLE, "store error");
    return OC_API_OK;
}

/* Calls with a leg on peer core_id. */
static uint8_t calls_with(const oc_api_t *a, uint16_t core_id)
{
    uint8_t n = 0;
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        const oc_core_call_t *k = &a->core->calls[i];
        n += k->used && ((k->a.kind == OC_CORE_LEG_PEER && k->a.peer == core_id) ||
                         (k->b.kind == OC_CORE_LEG_PEER && k->b.peer == core_id));
    }
    return n;
}

static uint8_t op_ocss_status(call_t *c)
{
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    oc_api_peer_t p[OC_CORE_PEERS];
    unsigned n = c->a->peers != NULL ? c->a->peers(c->a->peers_ctx, p, OC_CORE_PEERS) : 0;
    list_start(&c->w);
    for (unsigned i = 0; i < n && i < OC_CORE_PEERS; i++) {
        wr_t row = { .n = 0 };
        p[i].addr[sizeof(p[i].addr) - 1] = '\0';
        wr_u16(&row, p[i].core_id);
        wr_u8(&row, p[i].dials);
        wr_u8(&row, p[i].state);
        wr_u32(&row, p[i].since);
        wr_u32(&row, p[i].last_rx);
        wr_u32(&row, p[i].last_tx);
        wr_u8(&row, calls_with(c->a, p[i].core_id));
        wr_u32(&row, p[i].dropped);
        wr_text(&row, p[i].addr);
        list_row(&c->w, row.b, row.n);
    }
    return OC_API_OK;
}

static uint8_t op_core_blocks(call_t *c)
{
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    list_start(&c->w);
    for (unsigned i = 0; i < c->a->route->n; i++) {
        const oc_core_block_t *b = &c->a->route->b[i];
        wr_t row = { .n = 0 };
        wr_u16(&row, b->block_idx);
        wr_u16(&row, b->home_core);
        wr_u8(&row, oc_core_route_home(c->a->route, b) ? 1 : 0); /* secondaries come with plan 11 */
        wr_text(&row, b->prefix);
        list_row(&c->w, row.b, row.n);
    }
    return OC_API_OK;
}

static uint8_t op_core_status(call_t *c)
{
    if (!rd_done(&c->r)) return fail(c, OC_API_INVALID, "malformed request");
    long long cells = 0, subs = 0;
    if (one_int(c->a, "SELECT count(*) FROM cell", NULL, &cells) != 0 ||
        one_int(c->a, "SELECT count(*) FROM subscriber WHERE activated = 1", NULL, &subs) != 0) {
        return fail(c, OC_API_UNAVAILABLE, "store error");
    }
    uint32_t linked_cells = 0;
    uint16_t calls = 0;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) linked_cells += c->a->core->links[i].used && c->a->core->links[i].cell_id != 0;
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) calls += c->a->core->calls[i].used != 0;
    wr_u16(&c->w, c->a->cfg->core_id);
    wr_u32(&c->w, (uint32_t)((c->a->now_us() - c->a->started_us) / 1000000u));
    wr_u32(&c->w, (uint32_t)cells);
    wr_u32(&c->w, linked_cells);
    wr_u32(&c->w, (uint32_t)subs);
    wr_u16(&c->w, calls);
    wr_text(&c->w, c->a->name);
    wr_text(&c->w, c->a->version);
    return OC_API_OK;
}

/* ---- rate limits ---- */

void oc_api_init(oc_api_t *a)
{
    for (unsigned op = 0; op < OC_API_OPS; op++) {
        memset(&a->rate[op], 0, sizeof(a->rate[op]));
        a->rate[op].per_hour = OPS[op].per_hour;
        a->rate[op].burst = OPS[op].burst;
        a->rate[op].milli = (uint64_t)OPS[op].burst * 1000u;
        a->rate[op].at_us = a->now_us();
    }
    a->started_us = a->now_us();
    a->sweep_at_us = a->started_us; /* the first tick sweeps */
}

int oc_api_rate_set(oc_api_t *a, const char *spec, char *err, size_t cap)
{
    char name[32], extra;
    unsigned long per_hour, burst;
    if (sscanf(spec, "%31s %lu %lu %c", name, &per_hour, &burst, &extra) != 3 || per_hour > 1000000ul ||
        burst < 1 || burst > 100000ul) {
        snprintf(err, cap, "api_rate = '%s': OP PER_HOUR BURST, e.g. sub.disable 30 10 (burst 1-100000)", spec);
        return -1;
    }
    for (unsigned op = 0; op < OC_API_OPS; op++) {
        if (strcmp(name, OPS[op].name) != 0) continue;
        a->rate[op].per_hour = (uint32_t)per_hour;
        a->rate[op].burst = (uint32_t)burst;
        a->rate[op].milli = (uint64_t)burst * 1000u;
        a->rate[op].at_us = a->now_us();
        return 0;
    }
    snprintf(err, cap, "api_rate = '%s': no operation '%s'", spec, name);
    return -1;
}

/* One call of op may go now: 1, or 0 (refused: the bucket is empty). */
static int allowed(oc_api_t *a, unsigned op)
{
    oc_api_rate_t *r = &a->rate[op];
    uint64_t now = a->now_us();
    uint64_t cap = (uint64_t)r->burst * 1000u;
    if (now > r->at_us) {
        uint64_t add = (now - r->at_us) * r->per_hour / 3600000u; /* thousandths of a call */
        r->milli = r->milli + add > cap ? cap : r->milli + add;
        if (add > 0 || r->milli == cap) r->at_us = now;
    }
    if (r->milli < 1000u) return 0;
    r->milli -= 1000u;
    return 1;
}

static void audit(oc_api_t *a, uint32_t actor, const char *opname, uint8_t status, const char *extra)
{
    oc_core_audit_t r;
    oc_core_store_t st = store(a);
    memset(&r, 0, sizeof(r));
    r.ts = a->unix_now();
    r.event = OC_CORE_AUDIT_API;
    memcpy(r.number, a->audit_number, OC_SIG_NUMBER_LEN);
    r.cell_id = a->audit_cell;
    snprintf(r.detail, sizeof(r.detail), "a%u %s %s%s%s", (unsigned)actor, opname, oc_api_status_name(status),
             extra[0] != '\0' ? " " : "", extra);
    oc_log_clean(r.detail);
    if (st.audit_add(st.ctx, &r) != 0) oc_log(OC_LOG_ERR, "api: audit write FAILED (%s)", r.detail);
}

/* A call's operation as the audit names it: "sub.create", or "op66". */
static const char *op_label(unsigned op, char buf[8])
{
    if (op > 0 && op < OC_API_OPS) return OPS[op].name;
    snprintf(buf, 8, "op%u", op & 0xffu);
    return buf;
}

/* The refusals a rate limit (bucket op) counted in a minute, as one record. */
static void audit_refusals(oc_api_t *a, unsigned op, uint64_t now)
{
    oc_api_rate_t *r = &a->rate[op];
    if (r->window_us == 0 || now < r->window_us) return;
    if (r->refused > 0) {
        char what[32];
        snprintf(what, sizeof(what), "x%u in 60 s", (unsigned)r->refused);
        memset(a->audit_number, 0, sizeof(a->audit_number));
        a->audit_cell = 0;
        audit(a, r->refused_actor, OPS[op].name, OC_API_RATE_LIMITED, what);
        oc_log(OC_LOG_WARNING, "api: %s: %u more calls refused by its rate limit", OPS[op].name, (unsigned)r->refused);
    }
    r->refused = 0;
    r->window_us = 0;
}

/* The read-only operations whose calls naming no number and no cell are
 * audited once a minute per actor (oc_api.h). */
static int quiet_op(unsigned op)
{
    return op == OC_API_CELL_STATUS || op == OC_API_CORE_STATUS || op == OC_API_CELL_RADIO || op == OC_API_REG_LIST ||
           op == OC_API_CDR_RECENT || op == OC_API_AUDIT_LIST || op == OC_API_OCSS_STATUS || op == OC_API_CORE_BLOCKS;
}

/* The minute's count of op's quiet calls, as one record; the minute closed.
 * Keeps the call being served's own audit fields. */
static void quiet_flush(oc_api_t *a, unsigned op)
{
    oc_api_quiet_t *q = &a->quiet[op];
    if (q->n > 0) {
        uint8_t number[OC_SIG_NUMBER_LEN];
        uint32_t cell = a->audit_cell;
        char what[sizeof(a->audit_what)], extra[32];
        memcpy(number, a->audit_number, sizeof(number));
        memcpy(what, a->audit_what, sizeof(what));
        memset(a->audit_number, 0, sizeof(a->audit_number));
        a->audit_cell = 0;
        snprintf(extra, sizeof(extra), "x%u in 60 s", (unsigned)q->n);
        audit(a, q->actor, OPS[op].name, OC_API_OK, extra);
        memcpy(a->audit_number, number, sizeof(number));
        a->audit_cell = cell;
        memcpy(a->audit_what, what, sizeof(what));
    }
    q->n = 0;
    q->window_us = 0;
}

/* 1: this call is counted in its minute, not audited as itself. */
static int quiet(oc_api_t *a, unsigned op, uint32_t actor, uint8_t status)
{
    static const uint8_t none[OC_SIG_NUMBER_LEN];
    if (status != OC_API_OK || !quiet_op(op) || a->audit_cell != 0 ||
        memcmp(a->audit_number, none, sizeof(none)) != 0) {
        return 0;
    }
    oc_api_quiet_t *q = &a->quiet[op];
    uint64_t now = a->now_us();
    if (q->window_us != 0 && now < q->window_us && q->actor == actor) {
        q->n++;
        return 1;
    }
    quiet_flush(a, op);
    q->actor = actor;
    q->window_us = now + 60000000u;
    return 0;
}

void oc_api_tick(oc_api_t *a)
{
    uint64_t now = a->now_us();
    for (unsigned op = 0; op < OC_API_OPS; op++) {
        audit_refusals(a, op, now);
        if (a->quiet[op].window_us != 0 && now >= a->quiet[op].window_us) {
            memset(a->audit_number, 0, sizeof(a->audit_number));
            a->audit_cell = 0;
            a->audit_what[0] = '\0';
            quiet_flush(a, op);
        }
    }
    if (now >= a->sweep_at_us) {
        a->sweep_at_us = now + 60000000u;
        int n = oc_api_release_expired(a, NULL);
        if (n < 0) oc_log(OC_LOG_ERR, "api: the release of expired numbers failed (store error): next in a minute");
        if (n > 0) oc_log(OC_LOG_INFO, "api: %d unactivated numbers released (their codes expired)", n);
    }
}

/* ---- dispatch ---- */

int oc_api_handle(oc_api_t *a, const uint8_t *frame, size_t n, oc_buf_t *out)
{
    if (n < 3u || n > OC_API_FRAME_MAX || (size_t)(frame[0] << 8 | frame[1]) != n - 2u) return -1;
    uint8_t op = frame[2];
    if (op & OC_API_ANSWER) return -1;
    call_t c;
    memset(&c, 0, sizeof(c));
    c.a = a;
    c.r.p = frame + 3;
    c.r.n = n - 3u;
    uint32_t req = rd_u32(&c.r), actor = rd_u32(&c.r);
    if (c.r.err) return -1;
    memset(a->audit_number, 0, sizeof(a->audit_number));
    a->audit_cell = 0;
    a->audit_what[0] = '\0';
    c.w.out = out;
    c.w.op = op;
    c.w.req = req;
    uint8_t status;
    char label[8];
    unsigned bucket = op < OC_API_OPS ? op : 0; /* 0: the operations the core does not have */
    if (!allowed(a, bucket)) {
        oc_api_rate_t *r = &a->rate[bucket];
        uint64_t now = a->now_us();
        audit_refusals(a, bucket, now); /* a minute that ended: its count first */
        r->refused_actor = actor;
        if (r->window_us == 0) { /* the first refusal in a minute: audited as itself */
            r->window_us = now + 60000000u;
            audit(a, actor, op_label(op, label), OC_API_RATE_LIMITED, "");
            oc_log(OC_LOG_WARNING, "api: %s refused by its rate limit (%u/h, burst %u)", OPS[bucket].name,
                   (unsigned)r->per_hour, (unsigned)r->burst);
        } else {
            r->refused++;
        }
        wr_start(&c.w, OC_API_RATE_LIMITED);
        wr_text(&c.w, "rate limited");
        wr_end(&c.w);
        return 0;
    } else if (op == 0 || op >= OC_API_OPS || op == OC_API_ROUTE_OFFER) {
        status = fail(&c, OC_API_UNSUPPORTED, op == OC_API_ROUTE_OFFER ? "route.offer comes with plan P5" : "no such operation");
    } else {
        wr_start(&c.w, OC_API_OK);
        switch (op) {
        case OC_API_NUM_FREE: status = op_num_free(&c); break;
        case OC_API_NUM_CHECK: status = op_num_check(&c); break;
        case OC_API_SUB_CREATE: status = op_sub_create(&c, 0); break;
        case OC_API_SUB_REISSUE: status = op_sub_create(&c, 1); break;
        case OC_API_SUB_STATUS: status = op_sub_status(&c); break;
        case OC_API_CDR_LIST: status = op_cdr_list(&c); break;
        case OC_API_CELL_ADD: status = op_cell_add(&c); break;
        case OC_API_CELL_SET_CERT:
        case OC_API_CELL_REVOKE: status = op_cell_change(&c, op); break;
        case OC_API_CELL_STATUS: status = op_cell_status(&c); break;
        case OC_API_CORE_STATUS: status = op_core_status(&c); break;
        case OC_API_CELL_RADIO: status = op_cell_radio(&c); break;
        case OC_API_REG_LIST: status = op_reg_list(&c); break;
        case OC_API_CDR_RECENT: status = op_cdr_recent(&c); break;
        case OC_API_AUDIT_LIST: status = op_audit_list(&c); break;
        case OC_API_OCSS_STATUS: status = op_ocss_status(&c); break;
        case OC_API_CORE_BLOCKS: status = op_core_blocks(&c); break;
        default: status = op_sub_change(&c, op, actor); break;
        }
        if (status == OC_API_OK && c.w.err) status = fail(&c, OC_API_UNAVAILABLE, "answer too long");
    }
    if (status == OC_API_OK) {
        wr_end(&c.w);
    } else {
        wr_start(&c.w, status);
        wr_text(&c.w, c.msg != NULL ? c.msg : oc_api_status_name(status));
        wr_end(&c.w);
    }
    if (!quiet(a, op, actor, status)) audit(a, actor, op_label(op, label), status, a->audit_what);
    return 0;
}
