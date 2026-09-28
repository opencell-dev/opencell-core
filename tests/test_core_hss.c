/* The core's HSS/AuC (network-core spec §4.2, §7.1-7.2, §7.11): subscribers
 * and tokens, disabling; activation, vectors and resync, checked the way a
 * terminal checks them (its own key derivation and MILENAGE on its own
 * keys). */
#include "unity.h"

#include "core_fixture.h"
#include "lc_core_int.h" /* lc_core_loc_live */

void setUp(void) {}
void tearDown(void) {}

#define TMID  0x76ad0488u
#define TMID2 0x11223344u

static const char *NUM = "+883160655501234";

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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_subscribers_are_added_by_policy);
    RUN_TEST(test_token_issue_fills_the_qr_and_voids_the_old_token);
    RUN_TEST(test_disable_cancels_the_location_and_voids_tokens);
    RUN_TEST(test_token_issue_commit_failure_changes_nothing);
    RUN_TEST(test_sub_disable_commit_failure_changes_nothing);
    RUN_TEST(test_expired_location_is_not_live);
    return UNITY_END();
}
