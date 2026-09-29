/* The core's HSS/AuC (network-core spec §4.2, §7.1-7.2, §7.11): subscribers
 * and tokens, disabling; activation, vectors and resync, checked the way a
 * terminal checks them (its own key derivation and MILENAGE on its own
 * keys). */
#include "unity.h"

#include "core_fixture.h"
#include "lc_core_int.h" /* lc_core_loc_live */
#include "lc_sig_keys.h"
#include "lc_sig_milenage.h"
#include "lc_sig_term.h"

void setUp(void) {}
void tearDown(void) {}

#define TMID  0x76ad0488u
#define TMID2 0x11223344u

static const char *NUM = "+883160655501234";

/* A terminal: its identity, the QR it scanned, and the K/OPc it derives. */
typedef struct {
    lc_sig_ident_t id;
    lc_sig_qr_t    qr;
    uint32_t       tmid;
    uint8_t        k[16], opc[16];
} term_t;

static void term(term_t *t, uint32_t tmid, uint8_t seed, const lc_sig_qr_t *qr)
{
    uint8_t r[32];
    memset(t, 0, sizeof(*t));
    memset(r, seed, 32);
    lc_sig_ident_new(&t->id, r);
    t->qr = *qr;
    t->tmid = tmid;
    lc_sig_act_keys(t->id.sk, qr->pkn, tmid, qr->token_id, t->k, t->opc);
}

/* ACT_FWD from cell_link for t, as the cell forwards its ACT_REQ. */
static const lc_core_msg_t *activate(uint32_t link, const term_t *t)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_ACT_FWD;
    m.u.act_fwd.req = 9;
    m.u.act_fwd.tmid = t->tmid;
    memcpy(m.u.act_fwd.token_id, t->qr.token_id, 8);
    memcpy(m.u.act_fwd.pkt, t->id.pk, 32);
    lc_sig_act_tag(t->qr.token_secret, t->tmid, t->id.pk, t->qr.token_id, m.u.act_fwd.tag);
    int from = NSENT;
    rx(link, &m);
    return sent_since(from, link, LC_CORE_ACT_RES);
}

static const lc_core_msg_t *ask_avs(uint32_t link, uint32_t tmid, uint8_t count)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.req = 3;
    m.u.av_req.tmid = tmid;
    m.u.av_req.count = count;
    int from = NSENT;
    rx(link, &m);
    return sent_since(from, link, LC_CORE_AV_RES);
}

/* What lc_sig_term does with AUTH_REQ: the SQN if MAC-A verifies, else -1. */
static int64_t terminal_sqn(const term_t *t, const lc_core_av_t *av)
{
    static const uint8_t zero[6] = { 0 }, amf[2] = { 0x80, 0x00 };
    lc_milenage_t o;
    uint8_t sqn[6];
    lc_milenage(t->k, t->opc, av->rand, zero, amf, &o);
    for (int i = 0; i < 6; i++) sqn[i] = (uint8_t)(av->autn[i] ^ o.ak[i]);
    lc_milenage(t->k, t->opc, av->rand, sqn, av->autn + 6, &o);
    if (!lc_sig_ct_equal(o.mac_a, av->autn + 8, 8) || memcmp(o.res, av->xres, 8) != 0) return -1;
    return (int64_t)lc_sig_sqn_get(sqn);
}

static lc_sig_qr_t issue(const char *num)
{
    uint8_t n[LC_SIG_NUMBER_LEN];
    lc_sig_qr_t qr;
    number(num, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_token_issue(&K, n, 3600, &qr));
    return qr;
}

/* A subscriber for NUM with a token, and cell 1 on link 10. */
static lc_sig_qr_t sub_world(void)
{
    uint8_t n[LC_SIG_NUMBER_LEN], got[LC_SIG_NUMBER_LEN];
    core_world();
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, n, got));
    hello(10, 1, 1);
    return issue(NUM);
}

static void put_location(uint32_t cell, uint32_t tmid)
{
    lc_core_loc_t l;
    memset(&l, 0, sizeof(l));
    number(NUM, l.number);
    l.cell_id = cell;
    l.tmid = tmid;
    l.expires = UNIX0 + 3600u;
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

static void test_subscribers_are_added_by_policy(void)
{
    uint8_t n[LC_SIG_NUMBER_LEN], got[LC_SIG_NUMBER_LEN];
    core_world();
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(&K.route, "8831606555", 2, 2)); /* another core's exchange */
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* 606-555 is core 2's */
    number("+883160677701234", n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, n, got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(n, got, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* exists */
    number("+883160677709911", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* reserved */
    number("+883185955520000", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* no block */
    for (int i = 0; i < 20; i++) { /* auto-assigned: in block 1, never in core 2's exchange */
        TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, NULL, got));
        const lc_core_block_t *b = lc_core_route_find(&K.route, got);
        TEST_ASSERT_EQUAL_UINT16(1, b->block_idx);
        TEST_ASSERT_FALSE(lc_core_number_reserved(got));
        lc_core_sub_t s;
        TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, got, &s));
        TEST_ASSERT_EQUAL_UINT8(LC_CORE_SUB_ACTIVE, s.state);
    }
}

static void test_token_issue_fills_the_qr_and_voids_the_old_token(void)
{
    lc_sig_qr_t qr = sub_world();
    lc_core_netkey_t key;
    TEST_ASSERT_EQUAL_INT(0, ST.netkey_get(ST.ctx, 1, &key));
    TEST_ASSERT_EQUAL_UINT16(1, qr.key_id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(key.pk, qr.pkn, 32);
    TEST_ASSERT_EQUAL_UINT16(1, lc_core_token_block(qr.token_id)); /* block 1 */
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 1u + 3600u, qr.expiry);
    lc_core_token_t t;
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &t));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(qr.token_secret, t.secret, 16);
    lc_sig_qr_t qr2 = issue(NUM);
    TEST_ASSERT_EQUAL_INT(-1, ST.token_get(ST.ctx, qr.token_id, &t)); /* at most one unused token */
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr2.token_id, &t));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_TOKEN_ISSUE));
    uint8_t n[LC_SIG_NUMBER_LEN];
    number("+883160655509999", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_token_issue(&K, n, 3600, &qr2)); /* not a subscriber */
}

/* NUM bound to TMID with qr's token used, as an activation leaves it (set
 * by hand: this test is about disabling). */
static void bind_by_hand(const lc_sig_qr_t *qr)
{
    lc_core_sub_t s;
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, qr->number, &s));
    s.activated = 1;
    s.tmid = TMID;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr->token_id, &tok));
    tok.used_at = UNIX0;
    tok.used_by_tmid = TMID;
    TEST_ASSERT_EQUAL_INT(0, ST.token_put(ST.ctx, &tok));
}

static void test_disable_cancels_the_location_and_voids_tokens(void)
{
    lc_sig_qr_t qr = sub_world();
    bind_by_hand(&qr);
    put_location(1, TMID);
    lc_sig_qr_t spare = issue(NUM);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    int from = NSENT;
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, n, NOW));
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_DISABLED, c->u.loc_cancel.cause);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n, &l));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL));
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(-1, ST.token_get(ST.ctx, spare.token_id, &tok));
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &tok)); /* the used one stays, for the record */
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_SUB_DISABLE));
    TEST_ASSERT_EQUAL_INT(-1, lc_core_token_issue(&K, n, 3600, &spare));
    number("+883160655509999", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_disable(&K, n, NOW)); /* not a subscriber */
}

/* A commit that fails leaves everything as it was: no token change, nothing
 * sent, no audit. */
static void test_token_issue_commit_failure_changes_nothing(void)
{
    lc_sig_qr_t qr = sub_world();
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    unsigned ntoken = MEM.d.ntoken;
    unsigned naudit = MEM.d.naudit;
    int from = NSENT;
    MEM.fail_commits = 1;
    lc_sig_qr_t qr2;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_token_issue(&K, n, 3600, &qr2));
    TEST_ASSERT_EQUAL_UINT(ntoken, MEM.d.ntoken);
    TEST_ASSERT_EQUAL_UINT(naudit, MEM.d.naudit);
    TEST_ASSERT_EQUAL_INT(from, NSENT);
    lc_core_token_t t;
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &t)); /* the old token, untouched */
    TEST_ASSERT_EQUAL_UINT32(0, t.used_at);
}

/* Same for disabling: a commit that fails leaves the subscriber active, its
 * location live, nothing sent, no audit. */
static void test_sub_disable_commit_failure_changes_nothing(void)
{
    lc_sig_qr_t qr = sub_world();
    bind_by_hand(&qr);
    put_location(1, TMID);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    unsigned naudit = MEM.d.naudit;
    int from = NSENT;
    MEM.fail_commits = 1;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_disable(&K, n, NOW));
    TEST_ASSERT_EQUAL_UINT(naudit, MEM.d.naudit);
    TEST_ASSERT_EQUAL_INT(from, NSENT);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, n, &s));
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_SUB_ACTIVE, s.state);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, n, &l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
}

/* An expired location is not live, and is gone once asked about. */
static void test_expired_location_is_not_live(void)
{
    sub_world();
    put_location(1, TMID);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, lc_core_loc_live(&K, n, &l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    NOW += 3600ull * 1000000u; /* the fixture's clock: UNIX0 + 1 + 3600 > expires */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_loc_live(&K, n, &l));
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n, &l));
}

static void test_activation_binds_and_confirms(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    const lc_core_msg_t *r = activate(10, &t);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT16(9, r->u.act_res.req);
    TEST_ASSERT_EQUAL_HEX32(TMID, r->u.act_res.tmid);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
    uint8_t conf[8];
    lc_sig_act_confirm(t.k, TMID, qr.token_id, conf); /* what the terminal expects */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(conf, r->u.act_res.msg.u.act_ack.confirm, 8);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(qr.number, r->u.act_res.msg.u.act_ack.number, LC_SIG_NUMBER_LEN);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(t.k, s.k, 16);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(t.opc, s.opc, 16);
    TEST_ASSERT_EQUAL_UINT64(0, s.sqn);
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &tok));
    TEST_ASSERT_NOT_EQUAL(0, tok.used_at);
    TEST_ASSERT_EQUAL_HEX32(TMID, tok.used_by_tmid);
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_ACTIVATE));

    unsigned commits = MEM.commits;
    r = activate(10, &t); /* its ACT_ACK was lost: the same answer, nothing changes */
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(conf, r->u.act_res.msg.u.act_ack.confirm, 8);
    TEST_ASSERT_EQUAL_UINT(commits, MEM.commits);
}

/* Review Focus 4: the store fails in the middle of an activation: no answer
 * (the terminal times out), the token is not consumed, and the same QR works
 * on the next attempt. */
static void test_failed_activation_commit_leaves_the_token_usable(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    MEM.fail_commits = 1;
    TEST_ASSERT_NULL(activate(10, &t));
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &tok));
    TEST_ASSERT_EQUAL_UINT32(0, tok.used_at);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(-1, ST.sub_by_tmid(ST.ctx, TMID, &s));
    const lc_core_msg_t *r = activate(10, &t);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
}

static uint8_t nak(uint32_t link, const term_t *t)
{
    const lc_core_msg_t *r = activate(link, t);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_NAK, r->u.act_res.msg.type);
    return r->u.act_res.msg.u.act_nak.reason;
}

static void test_activation_refusals(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;

    lc_sig_qr_t bad = qr;
    bad.token_secret[0] ^= 1; /* someone without the real QR */
    term(&t, TMID, 0x42, &bad);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_BAD_TAG, nak(10, &t));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_ACT_FAIL));

    bad = qr;
    bad.token_id[7] ^= 1; /* no such token */
    term(&t, TMID, 0x42, &bad);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_UNKNOWN, nak(10, &t));
    bad = qr;
    bad.token_id[1] = 2; /* a block this core is not home for */
    term(&t, TMID, 0x42, &bad);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_UNKNOWN, nak(10, &t));

    term(&t, TMID, 0x42, &qr);
    NOW += 3601000000ull; /* past the token's expiry */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_EXPIRED, nak(10, &t));

    qr = issue(NUM);
    term(&t, TMID, 0x42, &qr);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, activate(10, &t)->u.act_res.msg.type);
    term_t other;
    term(&other, TMID2, 0x99, &qr); /* the used QR, on another terminal */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_USED, nak(10, &other));
    term(&other, TMID, 0x99, &qr); /* the same TMID, another key pair */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_USED, nak(10, &other));

    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    qr = issue(NUM);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, n, NOW));
    term(&t, TMID2, 0x77, &qr); /* a disabled subscriber's token: void */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_UNKNOWN, nak(10, &t));
}

/* §7.1 step 4: re-activating on a new terminal cancels the old one's
 * location, at its cell, before ACT_RES goes out. */
static void test_reactivation_cancels_the_old_location_first(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    hello(20, 2, 1);
    put_location(2, TMID); /* registered on cell 2 */
    qr = issue(NUM);
    term(&t, TMID2, 0x55, &qr);
    int from = NSENT;
    const lc_core_msg_t *r = activate(10, &t);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
    const lc_core_msg_t *c = sent_since(from, 20, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, c->u.loc_cancel.cause);
    lc_core_loc_t l;
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n, &l));
    TEST_ASSERT_EQUAL_INT(-1, ST.sub_by_tmid(ST.ctx, TMID, &(lc_core_sub_t){ 0 }));
}

static void test_vectors_rise_and_are_committed_first(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    const lc_core_msg_t *r = ask_avs(10, TMID, 2);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(2, r->u.av_res.count);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(qr.number, r->u.av_res.number, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT64(1, terminal_sqn(&t, &r->u.av_res.av[0]));
    TEST_ASSERT_EQUAL_INT64(2, terminal_sqn(&t, &r->u.av_res.av[1]));
    lc_core_av_issued_t a;
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, qr.number, r->u.av_res.av[1].rand, &a));
    TEST_ASSERT_EQUAL_UINT32(1, a.cell_id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(r->u.av_res.av[1].xres, a.xres, 8);

    MEM.fail_commits = 1; /* the store can't commit: no vector may leave */
    r = ask_avs(10, TMID, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_UNAVAILABLE, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(0, r->u.av_res.count);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(2, s.sqn);

    core_restart(); /* SQN persists: the next vector continues from it */
    hello(11, 1, 1);
    r = ask_avs(11, TMID, 9); /* at most LC_CORE_AV_MAX */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_MAX, r->u.av_res.count);
    TEST_ASSERT_EQUAL_INT64(3, terminal_sqn(&t, &r->u.av_res.av[0]));
    TEST_ASSERT_EQUAL_INT64(6, terminal_sqn(&t, &r->u.av_res.av[3]));

    r = ask_avs(11, TMID2, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_NOT_ACTIVATED, r->u.av_res.status);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, n, NOW));
    r = ask_avs(11, TMID, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_DISABLED, r->u.av_res.status);
}

static void test_resync_takes_the_terminal_sqn(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    const lc_core_msg_t *r = ask_avs(10, TMID, 1);
    lc_core_av_t av = r->u.av_res.av[0];
    /* the terminal is at SQN 500: it answers AUTH_FAIL(2) with AUTS */
    static const uint8_t amf0[2] = { 0, 0 };
    lc_milenage_t o;
    uint8_t ms[6];
    lc_sig_sqn_put(ms, 500);
    lc_milenage(t.k, t.opc, av.rand, ms, amf0, &o);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_RESYNC;
    m.u.resync.tmid = TMID;
    memcpy(m.u.resync.rand, av.rand, 16);
    for (int i = 0; i < 6; i++) m.u.resync.auts[i] = (uint8_t)(ms[i] ^ o.ak_s[i]);
    memcpy(m.u.resync.auts + 6, o.mac_s, 8);
    int from = NSENT;
    rx(10, &m);
    r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(1, r->u.av_res.count);
    TEST_ASSERT_EQUAL_INT64(501, terminal_sqn(&t, &r->u.av_res.av[0]));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_RESYNC));

    m.u.resync.auts[13] ^= 1; /* forged */
    from = NSENT;
    rx(10, &m);
    r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_AUTH_FAILED, r->u.av_res.status);
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL));
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(501, s.sqn);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_subscribers_are_added_by_policy);
    RUN_TEST(test_token_issue_fills_the_qr_and_voids_the_old_token);
    RUN_TEST(test_disable_cancels_the_location_and_voids_tokens);
    RUN_TEST(test_token_issue_commit_failure_changes_nothing);
    RUN_TEST(test_sub_disable_commit_failure_changes_nothing);
    RUN_TEST(test_expired_location_is_not_live);
    RUN_TEST(test_activation_binds_and_confirms);
    RUN_TEST(test_failed_activation_commit_leaves_the_token_usable);
    RUN_TEST(test_activation_refusals);
    RUN_TEST(test_reactivation_cancels_the_old_location_first);
    RUN_TEST(test_vectors_rise_and_are_committed_first);
    RUN_TEST(test_resync_takes_the_terminal_sqn);
    return UNITY_END();
}
