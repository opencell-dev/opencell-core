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
    uint8_t h[16]; /* the cell checks the terminal's RES against HXRES (network-core spec §19.1) */
    if (!lc_sig_ct_equal(o.mac_a, av->autn + 8, 8) || lc_sig_hxres(av->rand, o.res, h) != 0 ||
        memcmp(h, av->hxres, 16) != 0) {
        return -1;
    }
    return (int64_t)lc_sig_sqn_get(sqn);
}

/* The terminal's RES for rand. */
static void terminal_res(const term_t *t, const uint8_t rand[16], uint8_t res[8])
{
    static const uint8_t zero[6] = { 0 }, amf[2] = { 0x80, 0x00 };
    lc_milenage_t o;
    lc_milenage(t->k, t->opc, rand, zero, amf, &o);
    memcpy(res, o.res, 8);
}

/* LOC_UPDATE from the cell on link. */
static void loc_claim(uint32_t link, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                      const uint8_t res[8])
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_UPDATE;
    m.u.loc_update.tmid = tmid;
    memcpy(m.u.loc_update.number, number, LC_SIG_NUMBER_LEN);
    memcpy(m.u.loc_update.rand, rand, 16);
    memcpy(m.u.loc_update.res, res, 8);
    rx(link, &m);
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
    static const uint8_t zero[16] = { 0 };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, c->u.loc_cancel.rand, 16); /* whatever it registered with */
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

/* Network-core spec §19.3: re-activation deletes the number's issued
 * vectors, so a vector of the old binding (old K) proves nothing for the new
 * one - not even claimed under the new terminal's TMID. The new binding's
 * own vectors do. */
static void test_reactivation_voids_the_old_bindings_vectors(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t, t2;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    lc_core_av_t old = ask_avs(10, TMID, 1)->u.av_res.av[0];
    uint8_t res[8];
    terminal_res(&t, old.rand, res);
    qr = issue(NUM);
    term(&t2, TMID2, 0x55, &qr);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, activate(10, &t2)->u.act_res.msg.type);
    lc_core_av_issued_t a;
    TEST_ASSERT_EQUAL_INT(-1, ST.av_get(ST.ctx, qr.number, old.rand, &a));
    loc_claim(10, TMID2, qr.number, old.rand, res);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, qr.number, &l));
    const lc_core_audit_t *au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_NOT_NULL(au);
    TEST_ASSERT_EQUAL_UINT32(1, au->cell_id);

    lc_core_av_t v = ask_avs(10, TMID2, 1)->u.av_res.av[0];
    terminal_res(&t2, v.rand, res);
    loc_claim(10, TMID2, qr.number, v.rand, res);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, qr.number, &l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_HEX32(TMID2, l.tmid);
}

/* Review Focus 6: the had_other path — a token activates a TMID some other
 * subscriber is currently bound to: that subscriber is unbound, and since
 * it had a live location, LOC_CANCEL goes to its cell too. */
static void test_reactivation_unbinds_the_tmids_other_subscriber_and_cancels_its_location(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t ta;
    term(&ta, TMID, 0x42, &qr);
    activate(10, &ta);
    put_location(1, TMID); /* NUM registered at cell 1 */

    uint8_t n2[LC_SIG_NUMBER_LEN], got[LC_SIG_NUMBER_LEN];
    number("+883160655501235", n2);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, n2, got));
    lc_sig_qr_t qr2 = issue("+883160655501235");
    term_t tb;
    term(&tb, TMID, 0x88, &qr2); /* the same TMID, another subscriber's QR */
    int from = NSENT;
    const lc_core_msg_t *r = activate(10, &tb);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, c->u.loc_cancel.cause);
    uint8_t n1[LC_SIG_NUMBER_LEN];
    number(NUM, n1);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n1, &l)); /* NUM's location is gone */
    lc_core_sub_t sa;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, n1, &sa));
    TEST_ASSERT_EQUAL_UINT8(0, sa.activated); /* NUM lost the TMID */
    TEST_ASSERT_EQUAL_UINT32(0, sa.tmid);
    lc_core_sub_t sb;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &sb)); /* now bound to n2 */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(n2, sb.number, LC_SIG_NUMBER_LEN);
}

/* Review Focus 3/6: a commit that fails during re-activation leaves the old
 * location exactly as it was: no LOC_CANCEL, nothing deleted, since loc_del
 * is now inside the same transaction as the bind. */
static void test_failed_reactivation_commit_leaves_the_old_location_untouched(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    lc_core_av_t v = ask_avs(10, TMID, 1)->u.av_res.av[0];
    put_location(1, TMID);
    qr = issue(NUM);
    term(&t, TMID2, 0x55, &qr);
    MEM.fail_commits = 1;
    int from = NSENT;
    TEST_ASSERT_NULL(activate(10, &t));
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_LOC_CANCEL));
    lc_core_loc_t l;
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, n, &l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_UINT32(TMID, l.tmid);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s)); /* still the old binding */
    lc_core_av_issued_t a;
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, n, v.rand, &a)); /* ...and its vectors (§19.3 undone too) */
}

/* §19.3 with a real re-activation: cell 1 got a vector and the terminal
 * answered it while cell 1 was cut off; meanwhile the number was re-activated
 * on TMID2 at cell 2, which deleted that vector. Cell 1's late LOC_UPDATE for
 * the old TMID no longer proves anything, but cell 1 is still told to drop
 * the registration (LOC_CANCEL(reactivated)) - a stale claim, not an
 * AUTH_FAIL. */
static void test_a_claim_from_before_a_reactivation_is_cancelled_back(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t, t2;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    lc_core_av_t v = ask_avs(10, TMID, 1)->u.av_res.av[0];
    uint8_t res[8];
    terminal_res(&t, v.rand, res); /* AUTH_RSP: the registration cell 1 will report late */
    hello(20, 2, 1);
    qr = issue(NUM);
    term(&t2, TMID2, 0x55, &qr);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, activate(20, &t2)->u.act_res.msg.type);
    int from = NSENT;
    loc_claim(10, TMID, qr.number, v.rand, res);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, c->u.loc_cancel.cause);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_LOC_CANCEL));
    TEST_ASSERT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL));
    const lc_core_audit_t *au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(au);
    TEST_ASSERT_EQUAL_UINT32(1, au->cell_id);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, qr.number, &l));
}

/* Task 12b carry: the audit log tells an unproven stale claim (a cell cut
 * off through a re-activation, or a cell probing TMIDs it heard on air)
 * apart from the real re-activation's own cancel. */
static void test_an_unproven_stale_claim_is_audited_apart(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t, t2;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    put_location(1, TMID);
    hello(20, 2, 1);
    qr = issue(NUM);
    term(&t2, TMID2, 0x55, &qr);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, activate(20, &t2)->u.act_res.msg.type);
    const lc_core_audit_t *au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL); /* the re-activation's */
    TEST_ASSERT_NOT_NULL(au);
    TEST_ASSERT_EQUAL_STRING("cause 2", au->detail);
    static const uint8_t zero[16] = { 0 };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, sent_since(0, 10, LC_CORE_LOC_CANCEL)->u.loc_cancel.rand, 16);
    unsigned n = MEM.d.naudit;
    uint8_t rand[16], res[8];
    memset(rand, 0x5a, 16); /* never issued: nothing proves it */
    memset(res, 0x17, 8);
    int from = NSENT;
    loc_claim(10, TMID, qr.number, rand, res);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, sent_since(from, 10, LC_CORE_LOC_CANCEL)->u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_UINT(n + 1u, MEM.d.naudit);
    au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_EQUAL_STRING("unproven stale claim, cause 2", au->detail);
    TEST_ASSERT_EQUAL_UINT32(1, au->cell_id);
    TEST_ASSERT_EQUAL_HEX32(TMID, au->tmid);
    TEST_ASSERT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL));
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
    uint8_t h[16]; /* the core keeps XRES; the cell got its hash */
    TEST_ASSERT_EQUAL_INT(0, lc_sig_hxres(a.rand, a.xres, h));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(h, r->u.av_res.av[1].hxres, 16);
    uint8_t res[8];
    terminal_res(&t, a.rand, res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(res, a.xres, 8);

    unsigned nav = MEM.d.nav; /* Review Focus 6: a failed vector commit leaves no av_issued row */
    MEM.fail_commits = 1; /* the store can't commit: no vector may leave */
    r = ask_avs(10, TMID, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_UNAVAILABLE, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(0, r->u.av_res.count);
    TEST_ASSERT_EQUAL_UINT(nav, MEM.d.nav);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(2, s.sqn);

    core_restart(); /* SQN persists: the next vector continues from it */
    hello(11, 1, 1);
    r = ask_avs(11, TMID, 9); /* at most LC_CORE_AV_MAX */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_MAX, r->u.av_res.count);
    TEST_ASSERT_EQUAL_INT64(3, terminal_sqn(&t, &r->u.av_res.av[0]));
    TEST_ASSERT_EQUAL_INT64(6, terminal_sqn(&t, &r->u.av_res.av[3]));

    r = ask_avs(11, TMID, 0); /* controller ruling: count 0 -> 1 */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(1, r->u.av_res.count);
    TEST_ASSERT_EQUAL_INT64(7, terminal_sqn(&t, &r->u.av_res.av[0]));

    r = ask_avs(11, TMID2, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_NOT_ACTIVATED, r->u.av_res.status);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, n, NOW));
    r = ask_avs(11, TMID, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_DISABLED, r->u.av_res.status);
}

/* Review Focus 1: the AV table is full (256 rows, a mem-store test hook: no
 * pruning happens on its own): the store refuses the new av_issued row,
 * which must fail the whole commit, not just be dropped on the floor while
 * a vector still goes out unbacked by a record. */
static void test_av_table_full_answers_unavailable(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    memset(MEM.d.av, 0, sizeof(MEM.d.av));
    MEM.d.nav = LC_CORE_MEM_AVS;
    const lc_core_msg_t *r = ask_avs(10, TMID, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_UNAVAILABLE, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(0, r->u.av_res.count);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(0, s.sqn); /* not advanced: the whole transaction undid */
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

/* Review Focus 4: a RESYNC whose RAND this core never issued to the number
 * is refused, even with an AUTS that verifies against it (the terminal's
 * real K/OPc, used here only to build the test message). */
static void test_resync_requires_an_issued_rand(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    uint8_t fake_rand[16];
    memset(fake_rand, 0x7a, 16);
    static const uint8_t amf0[2] = { 0, 0 };
    lc_milenage_t o;
    uint8_t ms[6];
    lc_sig_sqn_put(ms, 600);
    lc_milenage(t.k, t.opc, fake_rand, ms, amf0, &o);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_RESYNC;
    m.u.resync.tmid = TMID;
    memcpy(m.u.resync.rand, fake_rand, 16);
    for (int i = 0; i < 6; i++) m.u.resync.auts[i] = (uint8_t)(ms[i] ^ o.ak_s[i]);
    memcpy(m.u.resync.auts + 6, o.mac_s, 8);
    int from = NSENT;
    rx(10, &m);
    const lc_core_msg_t *r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_AUTH_FAILED, r->u.av_res.status);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(0, s.sqn); /* untouched */
}

/* Review Focus 4: TS 33.102 §6.3.5 step 2 - SQN_HE only ever moves forward.
 * Replaying an old, already-superseded (RAND, AUTS) still verifies (same K,
 * OPc), but must not roll SQN_HE back to it. */
static void test_resync_replay_does_not_roll_back_the_sqn(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    const lc_core_msg_t *r = ask_avs(10, TMID, 1);
    lc_core_av_t av0 = r->u.av_res.av[0];
    static const uint8_t amf0[2] = { 0, 0 };
    lc_milenage_t o;
    uint8_t ms[6];
    lc_sig_sqn_put(ms, 500);
    lc_milenage(t.k, t.opc, av0.rand, ms, amf0, &o);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_RESYNC;
    m.u.resync.tmid = TMID;
    memcpy(m.u.resync.rand, av0.rand, 16);
    for (int i = 0; i < 6; i++) m.u.resync.auts[i] = (uint8_t)(ms[i] ^ o.ak_s[i]);
    memcpy(m.u.resync.auts + 6, o.mac_s, 8);
    int from = NSENT;
    rx(10, &m); /* the first, legitimate resync: SQN_HE -> 500, vector 501 */
    r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    TEST_ASSERT_EQUAL_INT64(501, terminal_sqn(&t, &r->u.av_res.av[0]));

    from = NSENT; /* replay the exact same (RAND, AUTS): SQN_MS(500) is behind */
    rx(10, &m);
    r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    TEST_ASSERT_EQUAL_INT64(502, terminal_sqn(&t, &r->u.av_res.av[0])); /* continues on, not reset to 501 */
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(502, s.sqn);
}

/* Review Focus 6: a commit that fails during resync leaves the SQN and the
 * store exactly as they were: no vector, no rollback either way. */
static void test_resync_failed_commit_changes_nothing(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    const lc_core_msg_t *r = ask_avs(10, TMID, 1);
    lc_core_av_t av = r->u.av_res.av[0];
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
    unsigned nav = MEM.d.nav;
    MEM.fail_commits = 1;
    int from = NSENT;
    rx(10, &m);
    r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_UNAVAILABLE, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(0, r->u.av_res.count);
    TEST_ASSERT_EQUAL_UINT(nav, MEM.d.nav);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(1, s.sqn); /* still just the one vector from before: the resync never landed */
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
    RUN_TEST(test_reactivation_voids_the_old_bindings_vectors);
    RUN_TEST(test_a_claim_from_before_a_reactivation_is_cancelled_back);
    RUN_TEST(test_an_unproven_stale_claim_is_audited_apart);
    RUN_TEST(test_reactivation_unbinds_the_tmids_other_subscriber_and_cancels_its_location);
    RUN_TEST(test_failed_reactivation_commit_leaves_the_old_location_untouched);
    RUN_TEST(test_vectors_rise_and_are_committed_first);
    RUN_TEST(test_av_table_full_answers_unavailable);
    RUN_TEST(test_resync_takes_the_terminal_sqn);
    RUN_TEST(test_resync_requires_an_issued_rand);
    RUN_TEST(test_resync_replay_does_not_roll_back_the_sqn);
    RUN_TEST(test_resync_failed_commit_changes_nothing);
    return UNITY_END();
}
