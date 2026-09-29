/* The location registry (network-core spec §7.7-7.8, §8): a location moves
 * only on a LOC_UPDATE carrying the RES of a vector issued to that cell;
 * the cell left behind is told; stale claims are cancelled; purges and
 * pruning. */
#include "unity.h"

#include "core_fixture.h"
#include "lc_sig_keys.h"

void setUp(void) {}
void tearDown(void) {}

#define TMID  0x76ad0488u
#define TMID2 0x11223344u

static uint8_t N1[LC_SIG_NUMBER_LEN];

/* NUM activated on TMID (by hand: this test is about locations), cells 1
 * and 2 on links 10 and 20. */
static void reg_world(void)
{
    core_world();
    number("+883160655501234", N1);
    uint8_t got[LC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, N1, got));
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, N1, &s));
    s.activated = 1;
    s.tmid = TMID;
    memset(s.k, 0x4b, 16);
    memset(s.opc, 0x0c, 16);
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    hello(10, 1, 1);
    hello(20, 2, 1);
}

/* A vector for TMID issued to the cell on link; returns it. */
static lc_core_av_t vector_for(uint32_t link)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.tmid = TMID;
    m.u.av_req.count = 1;
    int from = NSENT;
    rx(link, &m);
    const lc_core_msg_t *r = sent_since(from, link, LC_CORE_AV_RES);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    return r->u.av_res.av[0];
}

static void loc_update(uint32_t link, uint32_t tmid, const lc_core_av_t *av)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_UPDATE;
    m.u.loc_update.tmid = tmid;
    memcpy(m.u.loc_update.number, N1, LC_SIG_NUMBER_LEN);
    memcpy(m.u.loc_update.rand, av->rand, 16);
    memcpy(m.u.loc_update.res, av->xres, 8);
    rx(link, &m);
}

static int where(lc_core_loc_t *l) { return ST.loc_get(ST.ctx, N1, l); }

static void test_proven_update_sets_the_location(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_HEX32(TMID, l.tmid);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 1u + 3600u, l.expires); /* 2 x period_s */
    lc_core_av_issued_t a;
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, N1, av.rand, &a));
    TEST_ASSERT_EQUAL_UINT8(1, a.confirmed);
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_REGISTER));

    NOW += 600000000u; /* re-sent after a reconnect: still proves itself, and refreshes */
    loc_update(10, TMID, &av);
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 601u + 3600u, l.expires);
}

/* §7.8: the terminal registers on cell 2; cell 1 is told to drop it. */
static void test_move_cancels_at_the_old_cell(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    av = vector_for(20);
    int from = NSENT;
    loc_update(20, TMID, &av);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, c->u.loc_cancel.cause);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_LOC_CANCEL));
}

/* §8: a rogue cell can't pull a subscriber to itself: not with another
 * cell's vector, not with a wrong RES, not with a RAND never issued. */
static void test_rogue_claims_are_refused_and_audited(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    int from = NSENT;
    loc_update(20, TMID, &av); /* cell 1's vector, claimed by cell 2 */
    lc_core_av_t wrong = vector_for(20);
    wrong.xres[0] ^= 1;
    loc_update(20, TMID, &wrong);
    lc_core_av_t never = wrong;
    memset(never.rand, 0x5a, 16);
    loc_update(20, TMID, &never);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id); /* unmoved */
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_LOC_CANCEL));
    const lc_core_audit_t *a = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(2, a->cell_id);
}

/* A proven claim for a binding the core has since cancelled: the claiming
 * cell is told to drop it. */
static void test_stale_claims_are_cancelled_back(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, N1, &s));
    s.tmid = TMID2; /* re-activated on another terminal meanwhile */
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    int from = NSENT;
    loc_update(10, TMID, &av);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, c->u.loc_cancel.cause);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, where(&l));

    s.tmid = TMID;
    s.state = LC_CORE_SUB_DISABLED;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    from = NSENT;
    loc_update(10, TMID, &av);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_DISABLED, sent_since(from, 10, LC_CORE_LOC_CANCEL)->u.loc_cancel.cause);
}

static void test_purge_only_from_the_location_cell(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_PURGE;
    m.u.loc_purge.tmid = TMID;
    memcpy(m.u.loc_purge.number, N1, LC_SIG_NUMBER_LEN);
    rx(20, &m); /* not cell 2's to purge */
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    rx(10, &m);
    TEST_ASSERT_EQUAL_INT(-1, where(&l));
}

static void test_issued_vectors_are_pruned_after_a_day(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    lc_core_av_issued_t a;
    advance(1000000u); /* the first tick prunes nothing young */
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, N1, av.rand, &a));
    NOW += 86400ull * 1000000u;
    advance(3600ull * 1000000u); /* the hourly prune */
    TEST_ASSERT_EQUAL_INT(-1, ST.av_get(ST.ctx, N1, av.rand, &a));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_proven_update_sets_the_location);
    RUN_TEST(test_move_cancels_at_the_old_cell);
    RUN_TEST(test_rogue_claims_are_refused_and_audited);
    RUN_TEST(test_stale_claims_are_cancelled_back);
    RUN_TEST(test_purge_only_from_the_location_cell);
    RUN_TEST(test_issued_vectors_are_pruned_after_a_day);
    return UNITY_END();
}
