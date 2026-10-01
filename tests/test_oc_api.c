#define _GNU_SOURCE
/* The core admin API's protocol and operations (portal spec §7,
 * network-core spec §18.1, §18.3) on a core over the SQLite store, with no
 * TLS: request frames in, answer frames out, the audit and the store
 * checked. The golden frames here are the portal's test vectors too
 * (tests/unit/core-wire.test.ts there). */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oc_api.h"
#include "oc_sig_qr.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t KEY[32] = { 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7 };
#define UNIX0 1790000000u

static uint32_t rng = 5;
static uint64_t mono = 1000000u;   /* the test's monotonic clock, us */
static uint32_t wall = UNIX0;      /* ...and its wall clock, unix s */

static void rnd(uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((rng = rng * 1103515245u + 12345u) >> 16);
}
static uint64_t now_us(void) { return mono; }
static uint32_t unix_now(void) { return wall; }

static int k_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    (void)link;
    (void)m;
    return 0;
}
static void k_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    rnd(out, n);
}
static uint32_t k_unix(void *c)
{
    (void)c;
    return wall;
}

static oc_sql_t *sql;
static oc_core_route_t route;
static oc_core_cfg_t cfg;
static oc_core_t core;
static oc_api_t api;
static oc_buf_t out;

static void world(void)
{
    char err[256];
    oc_sql_cfg_t c = { ":memory:", KEY, rnd, NULL, 0 };
    mono = 1000000u;
    wall = UNIX0;
    sql = oc_sql_open(&c, err, sizeof(err));
    TEST_ASSERT_NOT_NULL_MESSAGE(sql, err);
    oc_core_route_init(&route, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&route, "8831717", 1, 1));
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&route, "8831717555", 2, 2)); /* another core's exchange */
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    oc_sig_number_to_bcd("+883160655500100", 16, cfg.echo_number);
    oc_core_store_t st = oc_sql_store(sql);
    uint8_t r[32];
    memset(r, 0x33, sizeof(r));
    TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&st, 1, 1800, r, UNIX0));
    const oc_core_io_t io = { NULL, k_send, NULL, k_random, k_unix, NULL };
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&core, &io, &st, &route, &cfg));
    memset(&api, 0, sizeof(api));
    api.sql = sql;
    api.route = &route;
    api.cfg = &cfg;
    api.core = &core;
    api.now_us = now_us;
    api.unix_now = unix_now;
    api.name = "oc-core-test";
    api.version = "v9.9.9";
    oc_api_init(&api);
}

static void done(void)
{
    oc_sql_close(sql);
    oc_buf_free(&out);
}

/* ---- frames ---- */

typedef struct {
    uint8_t b[OC_API_FRAME_MAX];
    size_t  n;
} req_t;

static void put(req_t *r, const void *p, size_t n)
{
    TEST_ASSERT_TRUE(r->n + n <= sizeof(r->b));
    memcpy(r->b + r->n, p, n);
    r->n += n;
}
static void put8(req_t *r, uint8_t v) { put(r, &v, 1); }
static void put16(req_t *r, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    put(r, b, 2);
}
static void put32(req_t *r, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    put(r, b, 4);
}
static void put_text(req_t *r, const char *s)
{
    put8(r, (uint8_t)strlen(s));
    put(r, s, strlen(s));
}
static void put_num(req_t *r, const char *text)
{
    uint8_t n[OC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(text, strlen(text), n));
    put(r, n, sizeof(n));
}
static void begin(req_t *r, uint8_t op, uint32_t req, uint32_t actor)
{
    r->n = 0;
    put16(r, 0);
    put8(r, op);
    put32(r, req);
    put32(r, actor);
}
static void finish(req_t *r)
{
    r->b[0] = (uint8_t)((r->n - 2u) >> 8);
    r->b[1] = (uint8_t)(r->n - 2u);
}

/* The answer frames of one call, split. */
typedef struct {
    const uint8_t *body; /* after status */
    size_t         n;
    uint8_t        op, status;
    uint32_t       req;
} ans_t;

static ans_t ANS[64];
static int NANS;

static int call(req_t *r)
{
    finish(r);
    out.n = 0;
    int rc = oc_api_handle(&api, r->b, r->n, &out);
    NANS = 0;
    for (size_t off = 0; rc == 0 && off < out.n;) {
        size_t len = (size_t)out.p[off] << 8 | (uint8_t)out.p[off + 1];
        TEST_ASSERT_TRUE(len >= 6 && off + 2 + len <= out.n && len + 2 <= OC_API_FRAME_MAX);
        const uint8_t *f = (const uint8_t *)out.p + off;
        ans_t *a = &ANS[NANS++];
        a->op = f[2];
        a->req = (uint32_t)f[3] | (uint32_t)f[4] << 8 | (uint32_t)f[5] << 16 | (uint32_t)f[6] << 24;
        a->status = f[7];
        a->body = f + 8;
        a->n = len - 6;
        off += 2 + len;
    }
    return rc;
}

/* One call answered by one frame: its status. */
static uint8_t call1(req_t *r)
{
    TEST_ASSERT_EQUAL_INT(0, call(r));
    TEST_ASSERT_EQUAL_INT(1, NANS);
    TEST_ASSERT_EQUAL_HEX8(OC_API_ANSWER | r->b[2], ANS[0].op);
    return ANS[0].status;
}

static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

static uint8_t num_op(uint8_t op, const char *number, uint32_t actor)
{
    req_t r;
    begin(&r, op, 1, actor);
    put_num(&r, number);
    return call1(&r);
}

static void num_text(const uint8_t *bcd, char out_text[OC_SIG_NUMBER_TEXT]) { oc_sig_number_to_text(bcd, out_text); }

/* The newest audit record: detail, and its number ("" if none). */
static void last_audit(char *detail, size_t cap, char *number, size_t ncap)
{
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(sql),
                                                        "SELECT detail, coalesce(number, '') FROM audit ORDER BY id DESC LIMIT 1",
                                                        -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    snprintf(detail, cap, "%s", (const char *)sqlite3_column_text(q, 0));
    snprintf(number, ncap, "%s", (const char *)sqlite3_column_text(q, 1));
    sqlite3_finalize(q);
}

static long count_rows(const char *sql_text)
{
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(sql), sql_text, -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    long n = (long)sqlite3_column_int64(q, 0);
    sqlite3_finalize(q);
    return n;
}

/* ---- tests ---- */

/* The bytes on the wire, pinned: the portal's codec tests use these. */
static void test_the_golden_frames(void)
{
    world();
    req_t r;
    begin(&r, OC_API_NUM_CHECK, 7, 42);
    put_num(&r, "+883171746412345");
    finish(&r);
    static const uint8_t want_req[] = { 0x00, 0x11, 0x02, 0x07, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
                                        0x88, 0x31, 0x71, 0x74, 0x64, 0x12, 0x34, 0x5f };
    TEST_ASSERT_EQUAL_UINT(sizeof(want_req), r.n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want_req, r.b, r.n);
    TEST_ASSERT_EQUAL_INT(0, call(&r));
    static const uint8_t want_ans[] = { 0x00, 0x07, 0x82, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }; /* ok, free */
    TEST_ASSERT_EQUAL_UINT(sizeof(want_ans), out.n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want_ans, out.p, out.n);

    begin(&r, OC_API_SUB_STATUS, 8, 42);
    put_num(&r, "+883171746412345");
    TEST_ASSERT_EQUAL_INT(0, call(&r));
    static const uint8_t want_err[] = { 0x00, 0x17, 0x85, 0x08, 0x00, 0x00, 0x00, 0x11, 0x10, 'n', 'o', 't', ' ',
                                        'a', ' ', 's', 'u', 'b', 's', 'c', 'r', 'i', 'b', 'e', 'r' };
    TEST_ASSERT_EQUAL_UINT(sizeof(want_err), out.n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want_err, out.p, out.n);
    done();
}

/* get a number, look at it, release it (portal spec §4.1-4.2). */
static void test_a_number_is_created_seen_and_released(void)
{
    world();
    const char *N = "+883171746412345";
    req_t r;
    begin(&r, OC_API_NUM_CHECK, 1, 42);
    put_num(&r, N);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[0]); /* free */

    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_CREATE, N, 42));
    char t[OC_SIG_NUMBER_TEXT];
    num_text(ANS[0].body, t);
    TEST_ASSERT_EQUAL_STRING(N, t);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + OC_API_TOKEN_S, get32(ANS[0].body + 8));
    uint8_t qlen = ANS[0].body[12];
    char qtext[200];
    memcpy(qtext, ANS[0].body + 13, qlen);
    qtext[qlen] = '\0';
    TEST_ASSERT_EQUAL_UINT(OC_SIG_QR_TEXT, qlen);
    oc_sig_qr_t qr;
    TEST_ASSERT_EQUAL_INT(0, oc_sig_qr_parse(qtext, qlen, &qr));
    num_text(qr.number, t);
    TEST_ASSERT_EQUAL_STRING(N, t);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + OC_API_TOKEN_S, qr.expiry);

    begin(&r, OC_API_NUM_CHECK, 1, 42);
    put_num(&r, N);
    call1(&r);
    TEST_ASSERT_EQUAL_UINT8(1, ANS[0].body[0]); /* taken */

    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_STATUS, N, 42));
    const uint8_t *b = ANS[0].body;
    TEST_ASSERT_EQUAL_UINT(8 + 1 + 1 + 4 + 1 + 4 + 2 + 4, ANS[0].n);
    TEST_ASSERT_EQUAL_UINT8(0, b[8]);  /* not activated */
    TEST_ASSERT_EQUAL_UINT8(0, b[9]);  /* not disabled */
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + OC_API_TOKEN_S, get32(b + 10));
    TEST_ASSERT_EQUAL_UINT8(0, b[14]); /* not registered */
    TEST_ASSERT_EQUAL_UINT32(0, get32(b + 15));
    TEST_ASSERT_EQUAL_UINT16(0, get16(b + 19));
    TEST_ASSERT_EQUAL_UINT32(0, get32(b + 21)); /* never seen */

    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_REISSUE, N, 42)); /* a new code voids the old */
    oc_sig_qr_t qr2;
    TEST_ASSERT_EQUAL_INT(0, oc_sig_qr_parse((const char *)ANS[0].body + 13, ANS[0].body[12], &qr2));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(qr.token_id, qr2.token_id, 8));
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM token WHERE used_at = 0"));

    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_RELEASE, N, 42));
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, num_op(OC_API_SUB_STATUS, N, 42));
    TEST_ASSERT_EQUAL_INT(0, (int)count_rows("SELECT count(*) FROM token WHERE used_at = 0"));
    begin(&r, OC_API_NUM_CHECK, 1, 42);
    put_num(&r, N);
    call1(&r);
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[0]); /* free again */
    done();
}

/* Each refusal has its own status, so the portal can say why. */
static void test_refusals_have_their_own_status(void)
{
    world();
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_ASSIGNABLE, num_op(OC_API_SUB_CREATE, "+883171746409911", 1)); /* reserved */
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_ASSIGNABLE, num_op(OC_API_SUB_CREATE, "+883171755501234", 1)); /* core 2's */
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_ASSIGNABLE, num_op(OC_API_SUB_CREATE, "+883160655501234", 1)); /* no block */
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_CREATE, "+883171746401000", 1));
    TEST_ASSERT_EQUAL_HEX8(OC_API_TAKEN, num_op(OC_API_SUB_CREATE, "+883171746401000", 1));
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, num_op(OC_API_SUB_REISSUE, "+883171746401001", 1));
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_RELEASE, "+883171746401001", 1)); /* free already: ok */
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, num_op(OC_API_SUB_DISABLE, "+883171746401001", 1));
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, num_op(OC_API_SUB_ENABLE, "+883171746401001", 1));

    /* an activated number is not released (the portal disables it instead) */
    oc_core_store_t st = oc_sql_store(sql);
    oc_core_sub_t s;
    uint8_t n[OC_SIG_NUMBER_LEN];
    oc_sig_number_to_bcd("+883171746401000", 16, n);
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, n, &s));
    s.activated = 1;
    s.tmid = 0x76ad0488u;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_UNACTIVATED, num_op(OC_API_SUB_RELEASE, "+883171746401000", 1));
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_DISABLE, "+883171746401000", 1));
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, num_op(OC_API_SUB_REISSUE, "+883171746401000", 1)); /* disabled */

    req_t r;
    begin(&r, OC_API_SUB_STATUS, 1, 1);
    put8(&r, 0x88); /* a number cut short */
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    begin(&r, OC_API_SUB_STATUS, 1, 1);
    put_num(&r, "+883171746401000");
    put8(&r, 0); /* a byte too many */
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    begin(&r, OC_API_SUB_STATUS, 1, 1);
    uint8_t bad[8] = { 0 };
    put(&r, bad, sizeof(bad)); /* not a number */
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    begin(&r, OC_API_NUM_CHECK, 1, 1);
    put(&r, bad, sizeof(bad));
    call1(&r);
    TEST_ASSERT_EQUAL_UINT8(2, ANS[0].body[0]); /* not assignable, as the fake core says */
    begin(&r, 0x42, 1, 1);
    TEST_ASSERT_EQUAL_HEX8(OC_API_UNSUPPORTED, call1(&r));
    begin(&r, OC_API_ROUTE_OFFER, 1, 1);
    put32(&r, 5);
    TEST_ASSERT_EQUAL_HEX8(OC_API_UNSUPPORTED, call1(&r));
    done();
}

/* Not requests at all: the caller closes the connection; nothing is audited. */
static void test_what_is_not_a_request_closes_the_connection(void)
{
    world();
    long before = count_rows("SELECT count(*) FROM audit");
    req_t r;
    begin(&r, OC_API_CORE_STATUS, 1, 1);
    finish(&r);
    r.b[1]++; /* a length that is not the frame's */
    out.n = 0;
    TEST_ASSERT_EQUAL_INT(-1, oc_api_handle(&api, r.b, r.n, &out));
    begin(&r, OC_API_ANSWER | OC_API_CORE_STATUS, 1, 1); /* an answer's type */
    finish(&r);
    TEST_ASSERT_EQUAL_INT(-1, oc_api_handle(&api, r.b, r.n, &out));
    r.n = 0;
    put16(&r, 0);
    put8(&r, OC_API_CORE_STATUS);
    put32(&r, 1); /* no actor */
    finish(&r);
    TEST_ASSERT_EQUAL_INT(-1, oc_api_handle(&api, r.b, r.n, &out));
    TEST_ASSERT_EQUAL_UINT(0, out.n);
    TEST_ASSERT_EQUAL_INT(before, count_rows("SELECT count(*) FROM audit"));
    done();
}

/* Every call is in the core's audit with the portal account it was for. */
static void test_every_call_is_audited_with_its_account(void)
{
    world();
    char detail[64], number[32];
    num_op(OC_API_SUB_CREATE, "+883171746412345", 42);
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a42 sub.create ok", detail);
    TEST_ASSERT_EQUAL_STRING("+883171746412345", number);
    num_op(OC_API_SUB_CREATE, "+883171746412345", 43);
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a43 sub.create taken", detail);
    req_t r;
    begin(&r, OC_API_NUM_FREE, 1, 7);
    put_text(&r, "8831717464");
    put8(&r, 3);
    put_text(&r, "");
    call1(&r);
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a7 num.free ok 8831717464 3", detail);
    TEST_ASSERT_EQUAL_STRING("", number);
    TEST_ASSERT_EQUAL_INT(3, (int)count_rows("SELECT count(*) FROM audit WHERE event = 11")); /* OC_CORE_AUDIT_API */
    TEST_ASSERT_EQUAL_INT(OC_CORE_AUDIT_API, 11);
    done();
}

/* The shortlist: free numbers in the exchange, as the pattern says. */
static void test_num_free_draws_free_numbers_in_the_exchange(void)
{
    world();
    for (int i = 0; i < 20; i++) {
        char n[32];
        snprintf(n, sizeof(n), "+8831717464%05d", 20000 + i);
        TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_CREATE, n, 1));
    }
    req_t r;
    begin(&r, OC_API_NUM_FREE, 1, 7);
    put_text(&r, "8831717464");
    put8(&r, 32);
    put_text(&r, "2xxxx");
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(32, ANS[0].body[0]);
    TEST_ASSERT_EQUAL_UINT(1 + 32 * 8, ANS[0].n);
    for (int i = 0; i < 32; i++) {
        char t[OC_SIG_NUMBER_TEXT];
        num_text(ANS[0].body + 1 + 8 * i, t);
        TEST_ASSERT_EQUAL_STRING_LEN("+88317174642", t, 12);
        int station = atoi(t + 11);
        TEST_ASSERT_TRUE(station < 20000 || station >= 20020); /* never a subscriber's */
        for (int j = 0; j < i; j++) TEST_ASSERT_NOT_EQUAL(0, memcmp(ANS[0].body + 1 + 8 * i, ANS[0].body + 1 + 8 * j, 8));
    }
    begin(&r, OC_API_NUM_FREE, 1, 7);
    put_text(&r, "8831717464");
    put8(&r, 5);
    put_text(&r, "20000"); /* one number fits, and it is taken */
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[0]);

    const char *bad_ex[] = { "8831717", "883171746x", "8831711464", "8832717464" };
    for (int i = 0; i < 4; i++) {
        begin(&r, OC_API_NUM_FREE, 1, 7);
        put_text(&r, bad_ex[i]);
        put8(&r, 5);
        put_text(&r, "");
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(OC_API_INVALID, call1(&r), bad_ex[i]);
    }
    begin(&r, OC_API_NUM_FREE, 1, 7);
    put_text(&r, "8831717555"); /* core 2's */
    put8(&r, 5);
    put_text(&r, "");
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_ASSIGNABLE, call1(&r));
    uint8_t counts[] = { 0, 33 };
    for (int i = 0; i < 2; i++) {
        begin(&r, OC_API_NUM_FREE, 1, 7);
        put_text(&r, "8831717464");
        put8(&r, counts[i]);
        put_text(&r, "");
        TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    }
    begin(&r, OC_API_NUM_FREE, 1, 7);
    put_text(&r, "8831717464");
    put8(&r, 5);
    put_text(&r, "12y45");
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    done();
}

static void test_disable_and_enable(void)
{
    world();
    const char *N = "+883171746412345";
    num_op(OC_API_SUB_CREATE, N, 1);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_DISABLE, N, 1));
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_DISABLE, N, 1)); /* again: nothing changes */
    num_op(OC_API_SUB_STATUS, N, 1);
    TEST_ASSERT_EQUAL_UINT8(1, ANS[0].body[9]);
    TEST_ASSERT_EQUAL_UINT32(0, get32(ANS[0].body + 10)); /* a disable voids its code */
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_ENABLE, N, 1));
    num_op(OC_API_SUB_STATUS, N, 1);
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[9]);
    done();
}

/* A registered terminal: the status says where, and when it was last heard. */
static void test_status_of_a_registered_terminal(void)
{
    world();
    const char *N = "+883171746412345";
    num_op(OC_API_SUB_CREATE, N, 1);
    oc_core_store_t st = oc_sql_store(sql);
    oc_core_sub_t s;
    uint8_t n[OC_SIG_NUMBER_LEN];
    oc_sig_number_to_bcd(N, 16, n);
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, n, &s));
    s.activated = 1;
    s.tmid = 0x76ad0488u;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    oc_core_loc_t l;
    memset(&l, 0, sizeof(l));
    memcpy(l.number, n, sizeof(n));
    l.cell_id = 3;
    l.tmid = s.tmid;
    l.expires = UNIX0 + 100u + 2u * 1800u; /* refreshed at UNIX0 + 100 */
    TEST_ASSERT_EQUAL_INT(0, st.loc_put(st.ctx, &l));
    wall = UNIX0 + 200u;
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_STATUS, N, 1));
    const uint8_t *b = ANS[0].body;
    TEST_ASSERT_EQUAL_UINT8(1, b[8]);
    TEST_ASSERT_EQUAL_UINT32(0, get32(b + 10)); /* no token shown once activated */
    TEST_ASSERT_EQUAL_UINT8(1, b[14]);
    TEST_ASSERT_EQUAL_UINT32(3, get32(b + 15));
    TEST_ASSERT_EQUAL_HEX16(0x76ad, get16(b + 19));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 100u, get32(b + 21));
    wall = UNIX0 + 100u + 2u * 1800u + 1u; /* lapsed: not registered, still last seen then */
    num_op(OC_API_SUB_STATUS, N, 1);
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[14]);
    TEST_ASSERT_EQUAL_UINT32(0, get32(ANS[0].body + 15));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 100u, get32(ANS[0].body + 21));
    done();
}

/* Calls: newest first, across as many frames as they need. */
static void test_cdr_list_spans_frames(void)
{
    world();
    oc_core_store_t st = oc_sql_store(sql);
    const char *me = "+883171746412345", *peer = "+883171746400777";
    for (int i = 0; i < 50; i++) {
        oc_core_cdr_t c;
        memset(&c, 0, sizeof(c));
        oc_sig_number_to_bcd(i % 2 ? me : peer, 16, c.caller);
        oc_sig_number_to_bcd(i % 2 ? peer : me, 16, c.called);
        c.setup = UNIX0 + 10u * (uint32_t)i;
        c.answer = i % 3 ? c.setup + 2u : 0;
        c.end = c.setup + 30u;
        c.cause = (uint8_t)(i % 3 ? 0 : 2);
        TEST_ASSERT_EQUAL_INT(0, st.cdr_add(st.ctx, &c));
    }
    req_t r;
    begin(&r, OC_API_CDR_LIST, 9, 1);
    put_num(&r, me);
    put32(&r, UNIX0 + 100u); /* calls 10..49 */
    TEST_ASSERT_EQUAL_INT(0, call(&r));
    TEST_ASSERT_TRUE(NANS >= 2);
    int total = 0;
    uint32_t prev = 0xFFFFFFFFu;
    for (int f = 0; f < NANS; f++) {
        TEST_ASSERT_EQUAL_HEX8(f + 1 < NANS ? OC_API_MORE : OC_API_OK, ANS[f].status);
        TEST_ASSERT_EQUAL_UINT32(9, ANS[f].req);
        uint8_t rows = ANS[f].body[0];
        TEST_ASSERT_EQUAL_UINT(1u + rows * 22u, ANS[f].n);
        for (int i = 0; i < rows; i++) {
            const uint8_t *row = ANS[f].body + 1 + 22 * i;
            uint32_t setup = get32(row);
            TEST_ASSERT_TRUE(setup < prev);
            prev = setup;
            int k = (int)((setup - UNIX0) / 10u);
            TEST_ASSERT_EQUAL_UINT32(k % 3 ? setup + 2u : 0, get32(row + 4));
            TEST_ASSERT_EQUAL_UINT32(setup + 30u, get32(row + 8));
            TEST_ASSERT_EQUAL_UINT8(k % 3 ? 0 : 2, row[12]);
            TEST_ASSERT_EQUAL_UINT8(k % 2 ? 0 : 1, row[13]); /* 0: me calling */
            char t[OC_SIG_NUMBER_TEXT];
            num_text(row + 14, t);
            TEST_ASSERT_EQUAL_STRING(peer, t);
            total++;
        }
    }
    TEST_ASSERT_EQUAL_INT(40, total);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 100u, prev);
    done();
}

/* Cells: added with the next id, pinned, looked at, revoked (unpinned). */
static void test_cells_are_added_pinned_and_revoked(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&core, 1, "bench", OC_SIG_MODE_PART15, 0)); /* the bench cell */
    req_t r;
    begin(&r, OC_API_CELL_ADD, 1, 5);
    put_text(&r, "Lancaster 1");
    put8(&r, 2);
    put16(&r, 7);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT32(2, get32(ANS[0].body));
    uint8_t fpr[32];
    for (int i = 0; i < 32; i++) fpr[i] = (uint8_t)(0xa0 + i);
    begin(&r, OC_API_CELL_SET_CERT, 1, 5);
    put32(&r, 2);
    put(&r, fpr, 32);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));

    begin(&r, OC_API_CELL_STATUS, 1, 5);
    put32(&r, 2);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    const uint8_t *row = ANS[0].body + 1;
    TEST_ASSERT_EQUAL_UINT8(1, ANS[0].body[0]);
    TEST_ASSERT_EQUAL_UINT32(2, get32(row));
    TEST_ASSERT_EQUAL_UINT8(1, row[4]);            /* enabled */
    TEST_ASSERT_EQUAL_UINT8(2, row[5]);            /* part97 */
    TEST_ASSERT_EQUAL_UINT16(7, get16(row + 6));   /* group */
    TEST_ASSERT_EQUAL_UINT8(1, row[8]);            /* pinned */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(fpr, row + 9, 32);
    TEST_ASSERT_EQUAL_UINT8(0, row[41]);           /* not linked */
    TEST_ASSERT_EQUAL_UINT16(0, get16(row + 46));  /* terminals */
    TEST_ASSERT_EQUAL_UINT16(0, get16(row + 48));  /* calls */
    TEST_ASSERT_EQUAL_UINT8(11, row[50]);
    TEST_ASSERT_EQUAL_STRING_LEN("Lancaster 1", (const char *)row + 51, 11);

    begin(&r, OC_API_CELL_STATUS, 1, 5);
    put32(&r, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(2, ANS[0].body[0]);

    begin(&r, OC_API_CELL_REVOKE, 1, 5);
    put32(&r, 2);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    begin(&r, OC_API_CELL_STATUS, 1, 5);
    put32(&r, 2);
    call1(&r);
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[1 + 4]); /* revoked */
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[1 + 8]); /* unpinned */
    begin(&r, OC_API_CELL_SET_CERT, 1, 5);
    put32(&r, 2);
    put(&r, fpr, 32);
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r)); /* revoked: not pinned again */
    begin(&r, OC_API_CELL_REVOKE, 1, 5);
    put32(&r, 9);
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, call1(&r));
    begin(&r, OC_API_CELL_STATUS, 1, 5);
    put32(&r, 9);
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, call1(&r));
    begin(&r, OC_API_CELL_ADD, 1, 5);
    put_text(&r, "bad\nname");
    put8(&r, 1);
    put16(&r, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    begin(&r, OC_API_CELL_ADD, 1, 5);
    put_text(&r, "x");
    put8(&r, 3); /* no such mode */
    put16(&r, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    done();
}

static void test_core_status(void)
{
    world();
    mono += 5000000u;
    num_op(OC_API_SUB_CREATE, "+883171746412345", 1);
    req_t r;
    begin(&r, OC_API_CORE_STATUS, 3, 1);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    const uint8_t *b = ANS[0].body;
    TEST_ASSERT_EQUAL_UINT16(1, get16(b));
    TEST_ASSERT_EQUAL_UINT32(5, get32(b + 2));  /* uptime */
    TEST_ASSERT_EQUAL_UINT32(0, get32(b + 6));  /* cells */
    TEST_ASSERT_EQUAL_UINT32(0, get32(b + 10)); /* linked */
    TEST_ASSERT_EQUAL_UINT32(0, get32(b + 14)); /* activated subscribers */
    TEST_ASSERT_EQUAL_UINT16(0, get16(b + 18));
    TEST_ASSERT_EQUAL_UINT8(12, b[20]);
    TEST_ASSERT_EQUAL_STRING_LEN("oc-core-test", (const char *)b + 21, 12);
    TEST_ASSERT_EQUAL_UINT8(6, b[33]);
    TEST_ASSERT_EQUAL_STRING_LEN("v9.9.9", (const char *)b + 34, 6);
    done();
}

/* A compromised portal can't mass-disable quickly (portal spec §7): past
 * its burst an operation is refused until its bucket refills; the first
 * refusal in a minute is audited, the rest counted into one record. */
static void test_rate_limits_refuse_and_are_audited_once_a_minute(void)
{
    world();
    char err[128], detail[64], number[32];
    TEST_ASSERT_EQUAL_INT(0, oc_api_rate_set(&api, "sub.disable 60 2", err, sizeof(err)));
    const char *N = "+883171746412345";
    num_op(OC_API_SUB_CREATE, N, 1);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_DISABLE, N, 9));
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_DISABLE, N, 9));
    long before = count_rows("SELECT count(*) FROM audit");
    TEST_ASSERT_EQUAL_HEX8(OC_API_RATE_LIMITED, num_op(OC_API_SUB_DISABLE, N, 9));
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a9 sub.disable rate_limited", detail);
    for (int i = 0; i < 5; i++) TEST_ASSERT_EQUAL_HEX8(OC_API_RATE_LIMITED, num_op(OC_API_SUB_DISABLE, N, 9));
    TEST_ASSERT_EQUAL_INT(before + 1, count_rows("SELECT count(*) FROM audit"));
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_STATUS, N, 9)); /* other operations go on */
    mono += 30000000u; /* 30 s: half a call back, still refused */
    TEST_ASSERT_EQUAL_HEX8(OC_API_RATE_LIMITED, num_op(OC_API_SUB_DISABLE, N, 9));
    mono += 30000000u; /* the minute is over: its count is one record */
    oc_api_tick(&api);
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a9 sub.disable rate_limited x6 in 60 s", detail);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_DISABLE, N, 9)); /* one call back after a minute */
    TEST_ASSERT_EQUAL_HEX8(OC_API_RATE_LIMITED, num_op(OC_API_SUB_DISABLE, N, 9));

    TEST_ASSERT_EQUAL_INT(-1, oc_api_rate_set(&api, "sub.frob 1 1", err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "no operation 'sub.frob'"));
    TEST_ASSERT_EQUAL_INT(-1, oc_api_rate_set(&api, "sub.disable 10", err, sizeof(err)));
    TEST_ASSERT_EQUAL_INT(-1, oc_api_rate_set(&api, "sub.disable 10 0", err, sizeof(err)));
    TEST_ASSERT_EQUAL_INT(-1, oc_api_rate_set(&api, "sub.disable 10 1 x", err, sizeof(err)));
    done();
}

/* Operations the core does not have (route.offer until P5, op 0, an
 * unknown op) are rate-limited like the rest: a flood of them is answered
 * rate_limited and adds a few audit records, not one per call. */
static void test_unsupported_operations_are_rate_limited_too(void)
{
    world();
    req_t r;
    long before = count_rows("SELECT count(*) FROM audit");
    int unsupported = 0, limited = 0;
    static const uint8_t ops[] = { OC_API_ROUTE_OFFER, 0x00, 0x42, 0x7f };
    for (int i = 0; i < 3000; i++) {
        begin(&r, ops[i % 4], (uint32_t)i, 9);
        put32(&r, 1);
        uint8_t st = call1(&r);
        if (st == OC_API_UNSUPPORTED) unsupported++;
        else if (st == OC_API_RATE_LIMITED) limited++;
        else TEST_FAIL_MESSAGE("neither unsupported nor rate_limited");
    }
    TEST_ASSERT_EQUAL_INT(3000, unsupported + limited);
    TEST_ASSERT_TRUE_MESSAGE(unsupported <= 12, "route.offer's burst (2) and the unknown ops' (10)");
    TEST_ASSERT_TRUE_MESSAGE(count_rows("SELECT count(*) FROM audit") - before <= 14, "one audit record per call");
    mono += 60000000u;
    oc_api_tick(&api); /* the minute's counts: one record for each bucket */
    TEST_ASSERT_TRUE(count_rows("SELECT count(*) FROM audit") - before <= 16);
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM audit"
                                             " WHERE detail LIKE 'a9 route.offer rate_limited x% in 60 s'"));
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM audit"
                                             " WHERE detail LIKE 'a9 unknown rate_limited x% in 60 s'"));
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_NUM_CHECK, "+883171746412345", 9)); /* the rest go on */
    done();
}

/* sub.release is idempotent: a number that is free already - released by
 * the 72 h job a moment before, or never taken - answers ok, so the
 * portal's account deletion never fails on a number the core freed. */
static void test_releasing_a_free_number_is_ok(void)
{
    world();
    char detail[64], number[32];
    const char *N = "+883171746412345";
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_CREATE, N, 1));
    wall = UNIX0 + OC_API_TOKEN_S; /* its code expired: the release before the call frees it */
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_RELEASE, N, 7));
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a7 sub.release ok free already", detail);
    TEST_ASSERT_EQUAL_STRING(N, number);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_RELEASE, N, 7)); /* and again */
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, num_op(OC_API_SUB_STATUS, N, 7));
    done();
}

/* sub.release_expired (network-core spec §18.3): an unactivated number
 * whose 72 h code has passed is free again - at once for a call about it,
 * and for every number at the minute's sweep. Activated numbers never go. */
static void test_expired_unactivated_numbers_are_released(void)
{
    world();
    num_op(OC_API_SUB_CREATE, "+883171746412345", 1);
    num_op(OC_API_SUB_CREATE, "+883171746412346", 1);
    num_op(OC_API_SUB_CREATE, "+883171746412347", 1);
    oc_core_store_t st = oc_sql_store(sql); /* the third one activated */
    oc_core_sub_t s;
    uint8_t n[OC_SIG_NUMBER_LEN];
    oc_sig_number_to_bcd("+883171746412347", 16, n);
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, n, &s));
    s.activated = 1;
    s.tmid = 0x11223344u;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    oc_api_tick(&api); /* the first sweep: nothing expired yet */
    TEST_ASSERT_EQUAL_INT(3, (int)count_rows("SELECT count(*) FROM subscriber"));

    wall = UNIX0 + OC_API_TOKEN_S - 1u;
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_STATUS, "+883171746412345", 1));
    wall = UNIX0 + OC_API_TOKEN_S; /* the code's expiry */
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, num_op(OC_API_SUB_STATUS, "+883171746412345", 1));
    char detail[64], number[32];
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(sql),
                                                        "SELECT detail, number FROM audit WHERE event = 12", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q)); /* OC_CORE_AUDIT_SUB_RELEASE */
    TEST_ASSERT_EQUAL_STRING("expired", (const char *)sqlite3_column_text(q, 0));
    TEST_ASSERT_EQUAL_STRING("+883171746412345", (const char *)sqlite3_column_text(q, 1));
    sqlite3_finalize(q);
    TEST_ASSERT_EQUAL_INT(OC_CORE_AUDIT_SUB_RELEASE, 12);

    mono += 59000000u;
    oc_api_tick(&api); /* 59 s after the last sweep: none yet */
    TEST_ASSERT_EQUAL_INT(2, (int)count_rows("SELECT count(*) FROM subscriber"));
    mono += 1000000u;
    oc_api_tick(&api);
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM subscriber")); /* the activated one stays */
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM subscriber WHERE number = '+883171746412347'"));
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("expired", detail);
    TEST_ASSERT_EQUAL_STRING("+883171746412346", number);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, num_op(OC_API_SUB_CREATE, "+883171746412346", 1)); /* free again */
    done();
}

/* The NOC's polls (NOC design §7): core.status and cell.status of every
 * cell are audited once a minute per account, the rest of the minute
 * counted into one record; a call naming a cell, another account, or a
 * failure is audited as itself. */
static void test_status_polls_are_audited_once_a_minute(void)
{
    world();
    char detail[64], number[32];
    req_t r;
    long before = count_rows("SELECT count(*) FROM audit");
    for (int i = 0; i < 5; i++) {
        begin(&r, OC_API_CORE_STATUS, 1, 0);
        TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
        begin(&r, OC_API_CELL_STATUS, 1, 0);
        put32(&r, 0);
        TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    }
    TEST_ASSERT_EQUAL_INT(before + 2, count_rows("SELECT count(*) FROM audit"));
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM audit WHERE detail = 'a0 core.status ok'"));
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM audit WHERE detail = 'a0 cell.status ok'"));

    /* another account opens its own minute; the first account's count is written then */
    begin(&r, OC_API_CORE_STATUS, 1, 7);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM audit WHERE detail = 'a0 core.status ok x4 in 60 s'"));
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a7 core.status ok", detail);

    /* a call that names a cell, or fails, is its own record */
    long n = count_rows("SELECT count(*) FROM audit");
    begin(&r, OC_API_CELL_STATUS, 1, 0);
    put32(&r, 9);
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, call1(&r));
    TEST_ASSERT_EQUAL_INT(n + 1, count_rows("SELECT count(*) FROM audit"));

    /* the minute ends: its count is one record, written at the tick */
    mono += 60000000u;
    oc_api_tick(&api);
    TEST_ASSERT_EQUAL_INT(1, (int)count_rows("SELECT count(*) FROM audit WHERE detail = 'a0 cell.status ok x4 in 60 s'"));
    begin(&r, OC_API_CELL_STATUS, 1, 0);
    put32(&r, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_INT(2, (int)count_rows("SELECT count(*) FROM audit WHERE detail = 'a0 cell.status ok'"));
    done();
}

/* Cell `cell_id` links (link `link`) and says HELLO, then reports one radio
 * and the terminals in tmids (RSSI -90 - i, SNR 20 + i, heard 3 s ago). */
static void cell_reports(uint32_t link, uint32_t cell_id, const uint32_t *tmids, uint8_t nt)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_HELLO;
    m.u.hello.proto = OC_CORE_PROTO;
    m.u.hello.cell_id = cell_id;
    m.u.hello.boot_id = 1;
    oc_core_link_up(&core, link, mono);
    oc_core_rx(&core, link, &m, mono);
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CELL_STATUS;
    m.u.cell_status.ver = OC_CORE_STATUS_VER;
    m.u.cell_status.part = OC_CORE_STATUS_LAST;
    m.u.cell_status.nradio = 1;
    oc_core_radio_t *x = &m.u.cell_status.radio[0];
    x->role = 1;
    x->fw[1] = 3;
    x->anchor = 30;
    x->pps = 1;
    x->timebase = 1;
    x->temp_c = 41;
    x->uptime_s = 3600;
    x->schedules = 30000;
    x->rach = 12;
    x->attach = 4;
    x->grants = 4;
    x->ack_err = 3;
    x->ack_late = 2;
    x->late_slots = 7;
    x->radio_errors = 1;
    x->last_radio_err = -2;
    x->sched_misses = 5;
    x->uart_crc = 0;
    m.u.cell_status.nterm = nt;
    for (uint8_t i = 0; i < nt; i++) {
        m.u.cell_status.term[i].tmid = tmids[i];
        m.u.cell_status.term[i].rssi_dbm = (int16_t)(-90 - i);
        m.u.cell_status.term[i].snr_qdb = (int16_t)(20 + i);
        m.u.cell_status.term[i].heard_age_s = 3;
    }
    oc_core_rx(&core, link, &m, mono);
}

/* A registration: number on cell_id as tmid, expiring at expires, with a REGISTER audit record at reg_ts. */
static void registered(const char *number, uint32_t cell_id, uint32_t tmid, uint32_t expires, uint32_t reg_ts)
{
    oc_core_store_t st = oc_sql_store(sql);
    oc_core_loc_t l;
    memset(&l, 0, sizeof(l));
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(number, strlen(number), l.number));
    l.cell_id = cell_id;
    l.tmid = tmid;
    l.expires = expires;
    TEST_ASSERT_EQUAL_INT(0, st.loc_put(st.ctx, &l));
    oc_core_audit_t a;
    memset(&a, 0, sizeof(a));
    a.ts = reg_ts;
    a.event = OC_CORE_AUDIT_REGISTER;
    memcpy(a.number, l.number, OC_SIG_NUMBER_LEN);
    a.tmid = tmid;
    a.cell_id = cell_id;
    snprintf(a.detail, sizeof(a.detail), "test");
    TEST_ASSERT_EQUAL_INT(0, st.audit_add(st.ctx, &a));
}

/* cell.radio (NOC design §7.1): each radio of each linked cell that has reported. */
static void test_cell_radio(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&core, 3, "Lancaster 1", OC_SIG_MODE_PART15, 0));
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&core, 4, "York 1", OC_SIG_MODE_PART15, 0));
    req_t r;
    begin(&r, OC_API_CELL_RADIO, 1, 0);
    put32(&r, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[0]); /* nobody linked */
    const uint32_t tmids[] = { 0x76ad0488u, 0x11220001u };
    wall = UNIX0 + 50u;
    cell_reports(1, 3, tmids, 2);
    begin(&r, OC_API_CELL_RADIO, 1, 0);
    put32(&r, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(1, ANS[0].body[0]);
    const uint8_t *row = ANS[0].body + 1;
    TEST_ASSERT_EQUAL_UINT32(3, get32(row));
    TEST_ASSERT_EQUAL_UINT8(0, row[4]);                       /* radio */
    TEST_ASSERT_EQUAL_UINT8(1, row[5]);                       /* role bs */
    TEST_ASSERT_EQUAL_UINT8(3, row[8]);                       /* fw 0.3.0 */
    TEST_ASSERT_EQUAL_UINT8(30, row[10]);                     /* anchor */
    TEST_ASSERT_EQUAL_UINT8(1, row[11]);                      /* PPS locked */
    TEST_ASSERT_EQUAL_INT8(41, (int8_t)row[13]);              /* temp */
    TEST_ASSERT_EQUAL_UINT32(3600, get32(row + 14));          /* board uptime */
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 50u, get32(row + 18));   /* reported at */
    TEST_ASSERT_EQUAL_UINT32(30000, get32(row + 22));         /* schedules */
    TEST_ASSERT_EQUAL_UINT32(2, get32(row + 42));             /* ACK late */
    TEST_ASSERT_EQUAL_UINT16(7, get16(row + 46));             /* late slots */
    TEST_ASSERT_EQUAL_INT16(-2, (int16_t)get16(row + 50));    /* last radio error */
    TEST_ASSERT_EQUAL_UINT16(5, get16(row + 52));             /* schedule misses */
    TEST_ASSERT_EQUAL_UINT8(2, row[56]);                      /* terminals heard */
    TEST_ASSERT_EQUAL_UINT(57, ANS[0].n - 1u);
    begin(&r, OC_API_CELL_RADIO, 1, 0);
    put32(&r, 4); /* exists, not linked: no rows */
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[0]);
    begin(&r, OC_API_CELL_RADIO, 1, 0);
    put32(&r, 9);
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, call1(&r));
    begin(&r, OC_API_CELL_RADIO, 1, 0);
    put16(&r, 0); /* too short */
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    done();
}

/* reg.list (NOC design §7.1): the live registrations, by number, with
 * their cell's signal for them and when they registered. */
static void test_reg_list(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&core, 3, "Lancaster 1", OC_SIG_MODE_PART15, 0));
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&core, 4, "York 1", OC_SIG_MODE_PART15, 0));
    wall = UNIX0 + 100u;
    const uint32_t tmids[] = { 0x76ad0488u };
    cell_reports(1, 3, tmids, 1);
    registered("+883171746412345", 3, 0x76ad0488u, UNIX0 + 3700u, UNIX0 + 90u);
    registered("+883171746400777", 3, 0x11220001u, UNIX0 + 3700u, UNIX0 + 80u); /* not in the cell's report */
    registered("+883171746455555", 4, 0x33440001u, UNIX0 + 3700u, UNIX0 + 70u);
    registered("+883171746466666", 4, 0x55660001u, UNIX0 + 99u, UNIX0 + 10u); /* expired */
    req_t r;
    begin(&r, OC_API_REG_LIST, 1, 0);
    put32(&r, 0);
    put(&r, (uint8_t[OC_SIG_NUMBER_LEN]){ 0 }, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(3, ANS[0].body[0]);
    const uint8_t *row = ANS[0].body + 1;
    char t[OC_SIG_NUMBER_TEXT];
    num_text(row, t);
    TEST_ASSERT_EQUAL_STRING("+883171746400777", t); /* by number */
    TEST_ASSERT_EQUAL_INT16(OC_CORE_STATUS_NONE, (int16_t)get16(row + 22));
    TEST_ASSERT_EQUAL_UINT32(0, get32(row + 26));
    row += 30;
    num_text(row, t);
    TEST_ASSERT_EQUAL_STRING("+883171746412345", t);
    TEST_ASSERT_EQUAL_HEX16(0x76ad, get16(row + 8));
    TEST_ASSERT_EQUAL_UINT32(3, get32(row + 10));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 90u, get32(row + 14));   /* registered at */
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 3700u, get32(row + 18)); /* expires */
    TEST_ASSERT_EQUAL_INT16(-90, (int16_t)get16(row + 22));
    TEST_ASSERT_EQUAL_INT16(20, (int16_t)get16(row + 24));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 97u, get32(row + 26));   /* heard 3 s before the report */
    row += 30;
    num_text(row, t);
    TEST_ASSERT_EQUAL_STRING("+883171746455555", t);

    begin(&r, OC_API_REG_LIST, 1, 0); /* one cell, after a number */
    put32(&r, 3);
    put_num(&r, "+883171746400777");
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(1, ANS[0].body[0]);
    num_text(ANS[0].body + 1, t);
    TEST_ASSERT_EQUAL_STRING("+883171746412345", t);

    begin(&r, OC_API_REG_LIST, 1, 0);
    put32(&r, 9);
    put(&r, (uint8_t[OC_SIG_NUMBER_LEN]){ 0 }, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8(OC_API_NOT_FOUND, call1(&r));
    begin(&r, OC_API_REG_LIST, 1, 0);
    put32(&r, 0);
    put(&r, (uint8_t[OC_SIG_NUMBER_LEN]){ 0x12, 0x34, 0, 0, 0, 0, 0, 0 }, OC_SIG_NUMBER_LEN); /* not a number */
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    done();
}

/* cdr.recent (NOC design §7.1): every CDR after an id, with both cells and
 * what each leg was, for the portal's copy of the calls. */
static void test_cdr_recent(void)
{
    world();
    oc_core_store_t st = oc_sql_store(sql);
    oc_core_cdr_t d;
    memset(&d, 0, sizeof(d));
    oc_sig_number_to_bcd("+883171746412345", 16, d.caller);
    oc_sig_number_to_bcd("+883171746400777", 16, d.called);
    d.cell_a = 3;
    d.cell_b = 4;
    d.setup = UNIX0 + 10u;
    d.answer = UNIX0 + 13u;
    d.end = UNIX0 + 70u;
    d.cause = 0;
    TEST_ASSERT_EQUAL_INT(0, st.cdr_add(st.ctx, &d));
    memcpy(d.called, cfg.echo_number, OC_SIG_NUMBER_LEN); /* to the echo service */
    d.cell_b = 0;
    TEST_ASSERT_EQUAL_INT(0, st.cdr_add(st.ctx, &d));
    oc_sig_number_to_bcd("+883150355501234", 16, d.called); /* to a peer core's subscriber */
    d.answer = 0;
    d.cause = 4;
    TEST_ASSERT_EQUAL_INT(0, st.cdr_add(st.ctx, &d));
    req_t r;
    begin(&r, OC_API_CDR_RECENT, 1, 0);
    put32(&r, 0);
    put16(&r, 1000);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(3, ANS[0].body[0]);
    const uint8_t *row = ANS[0].body + 1;
    TEST_ASSERT_EQUAL_UINT32(1, get32(row));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 10u, get32(row + 4));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 13u, get32(row + 8));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 70u, get32(row + 12));
    char t[OC_SIG_NUMBER_TEXT];
    num_text(row + 17, t);
    TEST_ASSERT_EQUAL_STRING("+883171746412345", t);
    num_text(row + 25, t);
    TEST_ASSERT_EQUAL_STRING("+883171746400777", t);
    TEST_ASSERT_EQUAL_UINT32(3, get32(row + 33));
    TEST_ASSERT_EQUAL_UINT32(4, get32(row + 37));
    TEST_ASSERT_EQUAL_HEX8(0x00, row[41]);         /* cell to cell */
    TEST_ASSERT_EQUAL_HEX8(0x01, row[42 + 41]);    /* cell to echo */
    TEST_ASSERT_EQUAL_HEX8(0x03, row[84 + 41]);    /* cell to a peer */
    TEST_ASSERT_EQUAL_UINT8(4, row[84 + 16]);      /* its cause */

    begin(&r, OC_API_CDR_RECENT, 1, 0); /* after id 2, one at most */
    put32(&r, 2);
    put16(&r, 1);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(1, ANS[0].body[0]);
    TEST_ASSERT_EQUAL_UINT32(3, get32(ANS[0].body + 1));
    begin(&r, OC_API_CDR_RECENT, 1, 0);
    put32(&r, 0);
    put16(&r, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    begin(&r, OC_API_CDR_RECENT, 1, 0);
    put32(&r, 0);
    put16(&r, 1001);
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    done();
}

/* audit.list (NOC design §7.1): the core's own audit after an id, by event
 * and by number; a look at one number's records is itself audited with it. */
static void test_audit_list(void)
{
    world();
    char detail[64], number[32];
    registered("+883171746412345", 3, 0x76ad0488u, UNIX0 + 3700u, UNIX0 + 90u);
    registered("+883171746400777", 3, 0x11220001u, UNIX0 + 3700u, UNIX0 + 80u);
    num_op(OC_API_SUB_STATUS, "+883171746412345", 9); /* an API record, about the number */
    req_t r;
    begin(&r, OC_API_AUDIT_LIST, 1, 0);
    put32(&r, 0);
    put32(&r, 1u << OC_CORE_AUDIT_REGISTER);
    put(&r, (uint8_t[OC_SIG_NUMBER_LEN]){ 0 }, OC_SIG_NUMBER_LEN);
    put16(&r, 500);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(2, ANS[0].body[0]);
    const uint8_t *row = ANS[0].body + 1;
    uint32_t first = get32(row);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 90u, get32(row + 4));
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_AUDIT_REGISTER, row[8]);
    char t[OC_SIG_NUMBER_TEXT];
    num_text(row + 9, t);
    TEST_ASSERT_EQUAL_STRING("+883171746412345", t);
    TEST_ASSERT_EQUAL_HEX16(0x76ad, get16(row + 17));
    TEST_ASSERT_EQUAL_UINT32(3, get32(row + 19));
    TEST_ASSERT_EQUAL_UINT8(4, row[23]);
    TEST_ASSERT_EQUAL_STRING_LEN("test", (const char *)row + 24, 4);

    begin(&r, OC_API_AUDIT_LIST, 1, 5); /* every event about one number, after the first REGISTER */
    put32(&r, first);
    put32(&r, 0);
    put_num(&r, "+883171746412345");
    put16(&r, 10);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(1, ANS[0].body[0]); /* the sub.status call's record */
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_AUDIT_API, ANS[0].body[1 + 8]);
    last_audit(detail, sizeof(detail), number, sizeof(number));
    TEST_ASSERT_EQUAL_STRING("a5 audit.list ok after 1", detail);
    TEST_ASSERT_EQUAL_STRING("+883171746412345", number);

    begin(&r, OC_API_AUDIT_LIST, 1, 0);
    put32(&r, 0);
    put32(&r, 0);
    put(&r, (uint8_t[OC_SIG_NUMBER_LEN]){ 0 }, OC_SIG_NUMBER_LEN);
    put16(&r, 501);
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    begin(&r, OC_API_AUDIT_LIST, 1, 0);
    put32(&r, 0);
    put32(&r, 0);
    put(&r, (uint8_t[OC_SIG_NUMBER_LEN]){ 0x12, 0x34, 0, 0, 0, 0, 0, 0 }, OC_SIG_NUMBER_LEN);
    put16(&r, 5);
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    done();
}

/* What the daemon would say about its OCSS peers (oc_core_main.c's api_peers). */
static unsigned fake_peers(void *ctx, oc_api_peer_t *out, unsigned cap)
{
    (void)ctx;
    TEST_ASSERT_TRUE(cap >= 2);
    memset(out, 0, 2 * sizeof(*out));
    out[0].core_id = 2;
    out[0].dials = 1;
    out[0].state = 4;
    out[0].since = UNIX0 + 5u;
    out[0].last_rx = UNIX0 + 60u;
    out[0].last_tx = UNIX0 + 61u;
    out[0].dropped = 3;
    snprintf(out[0].addr, sizeof(out[0].addr), "10.99.0.2:7443");
    out[1].core_id = 3;
    out[1].state = 0;
    snprintf(out[1].addr, sizeof(out[1].addr), "-");
    return 2;
}

/* ocss.status and core.blocks (NOC design §7.1). */
static void test_ocss_status_and_core_blocks(void)
{
    world();
    req_t r;
    begin(&r, OC_API_OCSS_STATUS, 1, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(0, ANS[0].body[0]); /* no OCSS configured */
    api.peers = fake_peers;
    core.calls[0].used = 1;
    core.calls[0].a.kind = OC_CORE_LEG_CELL;
    core.calls[0].a.cell = 3;
    core.calls[0].b.kind = OC_CORE_LEG_PEER;
    core.calls[0].b.peer = 2;
    begin(&r, OC_API_OCSS_STATUS, 1, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(2, ANS[0].body[0]);
    const uint8_t *row = ANS[0].body + 1;
    TEST_ASSERT_EQUAL_UINT16(2, get16(row));
    TEST_ASSERT_EQUAL_UINT8(1, row[2]);                     /* this core dials it */
    TEST_ASSERT_EQUAL_UINT8(4, row[3]);                     /* up */
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 5u, get32(row + 4));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 60u, get32(row + 8));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 61u, get32(row + 12));
    TEST_ASSERT_EQUAL_UINT8(1, row[16]);                    /* one call over it */
    TEST_ASSERT_EQUAL_UINT32(3, get32(row + 17));           /* frames dropped */
    TEST_ASSERT_EQUAL_UINT8(14, row[21]);
    TEST_ASSERT_EQUAL_STRING_LEN("10.99.0.2:7443", (const char *)row + 22, 14);
    row += 22 + 14;
    TEST_ASSERT_EQUAL_UINT16(3, get16(row));
    TEST_ASSERT_EQUAL_UINT8(0, row[3]);                     /* down */
    TEST_ASSERT_EQUAL_UINT8(0, row[16]);
    core.calls[0].used = 0;

    begin(&r, OC_API_CORE_BLOCKS, 1, 0);
    TEST_ASSERT_EQUAL_HEX8(OC_API_OK, call1(&r));
    TEST_ASSERT_EQUAL_UINT8(2, ANS[0].body[0]);
    row = ANS[0].body + 1;
    TEST_ASSERT_EQUAL_UINT16(1, get16(row));
    TEST_ASSERT_EQUAL_UINT16(1, get16(row + 2));
    TEST_ASSERT_EQUAL_UINT8(1, row[4]); /* home */
    TEST_ASSERT_EQUAL_UINT8(7, row[5]);
    TEST_ASSERT_EQUAL_STRING_LEN("8831717", (const char *)row + 6, 7);
    row += 6 + 7;
    TEST_ASSERT_EQUAL_UINT16(2, get16(row));
    TEST_ASSERT_EQUAL_UINT16(2, get16(row + 2));
    TEST_ASSERT_EQUAL_UINT8(0, row[4]); /* another core's */
    TEST_ASSERT_EQUAL_STRING_LEN("8831717555", (const char *)row + 6, 10);

    begin(&r, OC_API_CORE_BLOCKS, 1, 0);
    put8(&r, 1); /* a field it does not take */
    TEST_ASSERT_EQUAL_HEX8(OC_API_INVALID, call1(&r));
    done();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_the_golden_frames);
    RUN_TEST(test_a_number_is_created_seen_and_released);
    RUN_TEST(test_refusals_have_their_own_status);
    RUN_TEST(test_what_is_not_a_request_closes_the_connection);
    RUN_TEST(test_every_call_is_audited_with_its_account);
    RUN_TEST(test_num_free_draws_free_numbers_in_the_exchange);
    RUN_TEST(test_disable_and_enable);
    RUN_TEST(test_status_of_a_registered_terminal);
    RUN_TEST(test_cdr_list_spans_frames);
    RUN_TEST(test_cells_are_added_pinned_and_revoked);
    RUN_TEST(test_core_status);
    RUN_TEST(test_rate_limits_refuse_and_are_audited_once_a_minute);
    RUN_TEST(test_expired_unactivated_numbers_are_released);
    RUN_TEST(test_unsupported_operations_are_rate_limited_too);
    RUN_TEST(test_releasing_a_free_number_is_ok);
    RUN_TEST(test_status_polls_are_audited_once_a_minute);
    RUN_TEST(test_cell_radio);
    RUN_TEST(test_reg_list);
    RUN_TEST(test_cdr_recent);
    RUN_TEST(test_audit_list);
    RUN_TEST(test_ocss_status_and_core_blocks);
    return UNITY_END();
}
