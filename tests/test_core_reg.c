/* The location registry (network-core spec §7.7-7.8, §8): a location moves
 * only on a LOC_UPDATE carrying the RES of a vector issued to that cell;
 * the cell left behind is told; stale claims are cancelled; purges and
 * pruning. */
#include "unity.h"

#include "core_fixture.h"
#include "lc_sig_keys.h"
#include "lc_sig_milenage.h"

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

/* The AV_RES answering an AV_REQ for TMID from the cell on link. */
static const lc_core_msg_t *av_res_for(uint32_t link)
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
    return r;
}

/* A vector for TMID issued to the cell on link; returns it. */
static lc_core_av_t vector_for(uint32_t link) { return av_res_for(link)->u.av_res.av[0]; }

/* The RES the terminal (reg_world's K and OPc) answers rand with: only the
 * terminal can compute it; a cell has HXRES (network-core spec §19.1). */
static void terminal_res(const uint8_t rand[16], uint8_t res[8])
{
    static const uint8_t zero[6] = { 0 }, amf[2] = { 0x80, 0x00 };
    uint8_t k[16], opc[16];
    lc_milenage_t o;
    memset(k, 0x4b, 16);
    memset(opc, 0x0c, 16);
    TEST_ASSERT_EQUAL_INT(0, lc_milenage(k, opc, rand, zero, amf, &o));
    memcpy(res, o.res, 8);
}

static void loc_update_res(uint32_t link, uint32_t tmid, const uint8_t rand[16], const uint8_t res[8])
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_UPDATE;
    m.u.loc_update.tmid = tmid;
    memcpy(m.u.loc_update.number, N1, LC_SIG_NUMBER_LEN);
    memcpy(m.u.loc_update.rand, rand, 16);
    memcpy(m.u.loc_update.res, res, 8);
    rx(link, &m);
}

/* The terminal answered av's AUTH_REQ on the cell on link, which reports it. */
static void loc_update(uint32_t link, uint32_t tmid, const lc_core_av_t *av)
{
    uint8_t res[8];
    terminal_res(av->rand, res);
    loc_update_res(link, tmid, av->rand, res);
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
    TEST_ASSERT_EQUAL_UINT64(1, l.sqn);                      /* the proving vector's SQN (§19.2) */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(av.rand, l.rand, 16);       /* ...and RAND, for LOC_CANCEL */
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
    lc_core_av_t av = vector_for(10), first = av;
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
    TEST_ASSERT_EQUAL_HEX8_ARRAY(first.rand, c->u.loc_cancel.rand, 16); /* the registration it cancels */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_LOC_CANCEL));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(av.rand, l.rand, 16);
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
    uint8_t res[8];
    terminal_res(wrong.rand, res);
    res[0] ^= 1;
    loc_update_res(20, TMID, wrong.rand, res);
    uint8_t never[16];
    memset(never, 0x5a, 16);
    terminal_res(never, res); /* the right RES, for a RAND never issued */
    loc_update_res(20, TMID, never, res);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id); /* unmoved */
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_LOC_CANCEL));
    const lc_core_audit_t *a = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(2, a->cell_id);
}

/* A claim for a binding the core has since cancelled: the claiming cell is
 * told to drop it. Re-activated: the activation also deleted the number's
 * vectors (§19.3), so the claim no longer proves itself, and it is still
 * cancelled back (a stale claim, not an AUTH_FAIL). Disabled: the vector
 * still proves it, and the cell is told why. */
static void test_stale_claims_are_cancelled_back(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, N1, &s));
    s.tmid = TMID2; /* re-activated on another terminal meanwhile, as on_act_fwd commits it: */
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    TEST_ASSERT_EQUAL_INT(0, ST.av_del_number(ST.ctx, N1));
    int from = NSENT;
    loc_update(10, TMID, &av);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, c->u.loc_cancel.cause);
    static const uint8_t zero[16] = { 0 };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, c->u.loc_cancel.rand, 16); /* whatever it registered with */
    const lc_core_audit_t *au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL); /* sent and audited */
    TEST_ASSERT_NOT_NULL(au);
    TEST_ASSERT_EQUAL_UINT32(1, au->cell_id);
    TEST_ASSERT_EQUAL_HEX32(TMID, au->tmid);
    TEST_ASSERT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL));
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, where(&l));

    s.tmid = TMID; /* bound to TMID again, then disabled */
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    lc_core_av_t fresh = vector_for(10);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, N1, NOW));
    from = NSENT;
    loc_update(10, TMID, &fresh);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_DISABLED, sent_since(from, 10, LC_CORE_LOC_CANCEL)->u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, sent_since(from, 10, LC_CORE_LOC_CANCEL)->u.loc_cancel.rand, 16);
    from = NSENT;
    loc_update(10, TMID, &av); /* the deleted vector, for a disabled number: told too */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_DISABLED, sent_since(from, 10, LC_CORE_LOC_CANCEL)->u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_INT(-1, where(&l));
    TEST_ASSERT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL));
}

/* §19.1: a cell that heard TMID on air and asked for a vector itself gets
 * HXRES, not XRES; nothing it can compute from the vector proves a
 * registration that never happened, so the subscriber stays where it is. */
static void test_a_rogue_cell_cannot_prove_a_registration(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av); /* the terminal really is on cell 1 */
    int from = NSENT;
    const lc_core_msg_t *r = av_res_for(20); /* cell 2 asks for TMID's vector */
    lc_core_av_t v = r->u.av_res.av[0];
    lc_core_av_issued_t row;
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, N1, v.rand, &row));
    uint8_t buf[LC_CORE_FRAME_MAX];
    size_t n = lc_core_encode(r, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);
    for (size_t i = 0; i + 8u <= n; i++) TEST_ASSERT_FALSE(memcmp(buf + i, row.xres, 8) == 0); /* no XRES on the wire */
    static const uint8_t zero[8] = { 0 };
    const uint8_t *guess[] = { v.hxres, v.hxres + 8, v.autn, v.autn + 8, v.ck, v.ck + 8, v.ik, v.ik + 8, v.rand,
                               v.rand + 8, zero };
    for (unsigned i = 0; i < sizeof(guess) / sizeof(guess[0]); i++) loc_update_res(20, TMID, v.rand, guess[i]);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id); /* unmoved */
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_LOC_CANCEL));
    const lc_core_audit_t *a = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(2, a->cell_id);
}

/* §19.2 and §7.10: cell 1 registered the terminal while cut off (SQN 1);
 * the terminal then moved to cell 2 (SQN 2), which reported at once. When
 * cell 1 reconnects, its older claim is refused and it is told the terminal
 * moved; the location stays on cell 2. A newer claim still moves it back. */
static void test_an_older_claim_from_another_cell_is_refused(void)
{
    reg_world();
    lc_core_av_t va = vector_for(10);
    lc_core_av_t vb = vector_for(20);
    loc_update(20, TMID, &vb);
    int from = NSENT;
    loc_update(10, TMID, &va); /* the offline registration's LOC_UPDATE, replayed late */
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
    TEST_ASSERT_EQUAL_UINT64(2, l.sqn);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, c->u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(va.rand, c->u.loc_cancel.rand, 16); /* the refused claim's registration */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_LOC_CANCEL));
    const lc_core_audit_t *au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(au);
    TEST_ASSERT_EQUAL_UINT32(1, au->cell_id);
    TEST_ASSERT_EQUAL_STRING("older claim refused, cause 1", au->detail); /* a replay, told apart */
    lc_core_av_issued_t a;
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, N1, va.rand, &a));
    TEST_ASSERT_EQUAL_UINT8(0, a.confirmed); /* it proved nothing */

    lc_core_av_t va2 = vector_for(10); /* the terminal really came back: SQN 3 */
    from = NSENT;
    loc_update(10, TMID, &va2);
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_UINT64(3, l.sqn);
    c = sent_since(from, 20, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, c->u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(vb.rand, c->u.loc_cancel.rand, 16);
    au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_EQUAL_UINT32(2, au->cell_id);
    TEST_ASSERT_EQUAL_STRING("cause 1", au->detail); /* a normal move's cancel, as before */
}

static void purge(uint32_t link)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_PURGE;
    m.u.loc_purge.tmid = TMID;
    memcpy(m.u.loc_purge.number, N1, LC_SIG_NUMBER_LEN);
    rx(link, &m);
}

/* §19.2: the floor outlives the location. Cell 1 proved SQN 1, then cell 2
 * SQN 2; cell 2's location goes (a purge; later its new boot) and cell 1
 * replays SQN 1: refused (moved) on cell 2's confirmed vector. A newer
 * claim from cell 1 still proceeds. */
static void test_an_older_claim_is_refused_after_the_newer_location_went(void)
{
    reg_world();
    lc_core_av_t va = vector_for(10);
    loc_update(10, TMID, &va);
    lc_core_av_t vb = vector_for(20);
    loc_update(20, TMID, &vb);
    purge(20);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, where(&l));
    int from = NSENT;
    loc_update(10, TMID, &va);
    TEST_ASSERT_EQUAL_INT(-1, where(&l));
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, c->u.loc_cancel.cause);

    loc_update(20, TMID, &vb); /* cell 2 again (nothing newer elsewhere), then it reboots */
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
    hello(21, 2, 2);
    TEST_ASSERT_EQUAL_INT(-1, where(&l));
    from = NSENT;
    loc_update(10, TMID, &va);
    TEST_ASSERT_EQUAL_INT(-1, where(&l));
    TEST_ASSERT_NOT_NULL(sent_since(from, 10, LC_CORE_LOC_CANCEL));
    const lc_core_audit_t *au = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(au);
    TEST_ASSERT_EQUAL_UINT32(1, au->cell_id);
    TEST_ASSERT_EQUAL_STRING("older claim refused, cause 1", au->detail); /* refused by the floor */

    lc_core_av_t vc = vector_for(10); /* SQN 3: the terminal really is on cell 1 now */
    loc_update(10, TMID, &vc);
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_UINT64(3, l.sqn);
    loc_update(10, TMID, &va); /* and cell 1 re-sending its old claim refreshes, as before */
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_UINT64(3, l.sqn);
}

/* §19.2: the same cell re-sending a claim - even an older one than the
 * location holds - refreshes it as before; the location keeps its newest
 * SQN, so a later replay from elsewhere is still judged against that. */
static void test_the_same_cell_resending_still_refreshes(void)
{
    reg_world();
    lc_core_av_t v1 = vector_for(20);
    lc_core_av_t v2 = vector_for(20);
    loc_update(20, TMID, &v2);
    NOW += 600000000u;
    int from = NSENT;
    loc_update(20, TMID, &v1);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 601u + 3600u, l.expires);
    TEST_ASSERT_EQUAL_UINT64(2, l.sqn);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(v2.rand, l.rand, 16); /* the newest proof, with its SQN */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_LOC_CANCEL));
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
    m.u.loc_purge.tmid = TMID2; /* the right cell, but not the terminal registered there */
    rx(10, &m);
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    m.u.loc_purge.tmid = TMID;
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
    RUN_TEST(test_a_rogue_cell_cannot_prove_a_registration);
    RUN_TEST(test_an_older_claim_from_another_cell_is_refused);
    RUN_TEST(test_the_same_cell_resending_still_refreshes);
    RUN_TEST(test_an_older_claim_is_refused_after_the_newer_location_went);
    RUN_TEST(test_purge_only_from_the_location_cell);
    RUN_TEST(test_issued_vectors_are_pruned_after_a_day);
    return UNITY_END();
}
