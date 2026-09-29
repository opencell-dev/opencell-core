/* The multi-cell simulation (network-core spec §9.2): lc_sig_term terminals
 * on three cells (lc_cell) and one core (lc_core), over net_sim.h. Activation
 * and registration through the core; calls across cells and within one, the
 * refusals and their causes, the echo service; idle moves, re-activation
 * elsewhere, cell and core restarts, a backhaul outage, resync, and a rogue
 * cell. */
#include "unity.h"

#include "net_sim.h"

void setUp(void) {}
void tearDown(void) {}

static void test_activation_and_registration_through_the_core(void)
{
    sim_world();
    activate_on(0, 0);
    run_ms(8000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_ACTIVATED));
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(1, located(0)); /* cell 1 told the core (LOC_UPDATE) */
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    TEST_ASSERT_EQUAL_UINT64(lc_sig_sqn_get(TERM[0].id.sqn), s.sqn); /* terminal and HSS agree */
}

/* Review Focus 1: a terminal registers while its cell's core link is still
 * coming up (after a cell or core restart). The question waits for
 * HELLO_ACK and registration completes, instead of timing out and backing
 * off for 30 s. */
static void test_registration_while_the_core_link_comes_up(void)
{
    sim_world();
    registered_on(0, 0);
    sim_disconnect(0);
    const lc_sig_term_io_t io = TERM[0].t.io;
    lc_sig_term_init(&TERM[0].t, &io, &TERM[0].id, TERM[0].tmid, now); /* reboot: it registers again */
    forget_events();
    run_ms(1000); /* its REG_REQ reaches a cell without a core */
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    sim_connect(0);
    run_ms(2000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_REG_FAILED));
}

/* §7.10 and §19: T0 moves from cell 2 to cell 1, whose backhaul drops
 * after the vector came and before the terminal answered it. The
 * registration completes offline with the vector cell 1 already holds;
 * when the link is back, cell 1 reports it (LOC_UPDATE with the RAND and
 * the terminal's RES it kept), the core accepts it (its SQN is newer than
 * cell 2's location), and cell 2 is told the terminal moved. */
static void test_an_offline_registration_is_reported_when_the_link_is_back(void)
{
    sim_world();
    registered_on(0, 1);
    TEST_ASSERT_EQUAL_UINT32(2, located(0));
    TERM[0].cell = -1; /* out of cell 2's coverage */
    run_ms(2000);
    TERM[0].cell = 0; /* cell 1's beacon: it registers again by itself */
    forget_events();
    for (int k = 0; k < 100 && (sess_on(0, 0) == NULL || !sess_on(0, 0)->auth_pending); k++) frame();
    TEST_ASSERT_TRUE_MESSAGE(sess_on(0, 0)->auth_pending, "AUTH_REQ on its way");
    sim_disconnect(0);
    unsigned sent = to_core[0][LC_CORE_LOC_UPDATE];
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT(sent, to_core[0][LC_CORE_LOC_UPDATE]); /* no link: kept for later */
    TEST_ASSERT_EQUAL_UINT32(2, located(0));
    sim_connect(0);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT(sent + 1u, to_core[0][LC_CORE_LOC_UPDATE]);
    TEST_ASSERT_EQUAL_HEX32(TERM[0].tmid, last_loc_update[0].u.loc_update.tmid);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(sess_on(0, 0)->rand, last_loc_update[0].u.loc_update.rand, 16);
    TEST_ASSERT_EQUAL_UINT32(1, located(0)); /* proven by the terminal's RES */
    const lc_core_audit_t *a = lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_REGISTER);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(1, a->cell_id);
    TEST_ASSERT_NULL(lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_AUTH_FAIL));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));  /* not cancelled back */
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[1].c.net, TERM[0].tmid)); /* LOC_CANCEL(moved) */
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, SST.loc_get(SST.ctx, TERM[0].number, &l));
    lc_core_sub_t sub;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &sub));
    TEST_ASSERT_EQUAL_UINT64(sub.sqn, l.sqn); /* the newest vector proved it */
}

/* §7.1 step 4 and lc_sig_net_act_done's contract: T0, registered and
 * located on cell 1, scans a new code for its own number there. The core
 * sends LOC_CANCEL(reactivated, no RAND: whatever it registered with) and
 * then ACT_RES; the cell drops the old registration - its RAND and RES
 * wiped - without losing the open activation, so the terminal is activated,
 * and it registers again with the new keys. */
static void test_reactivation_drops_the_old_registration_first(void)
{
    static const uint8_t zero[16] = { 0 };
    static const lc_cell_reg_t none;
    sim_world();
    registered_on(0, 0);
    const lc_cell_reg_t *r = reg_on(0, 0);
    TEST_ASSERT_NOT_NULL(r);
    const lc_cell_reg_t *slot = r;
    forget_events();
    activate_on(0, 0);
    TEST_ASSERT_TRUE(run_until_event(0, LC_SIG_EV_ACTIVATED, 3000));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid)); /* dropped before the ACT_ACK */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, last_loc_cancel[0].u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, last_loc_cancel[0].u.loc_cancel.rand, 16);
    TEST_ASSERT_NULL(reg_on(0, 0));
    TEST_ASSERT_EQUAL_MEMORY(&none, slot, sizeof(none)); /* RAND and RES wiped */
    TEST_ASSERT_EQUAL_UINT32(0, located(0));
    run_ms(5000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    TEST_ASSERT_EQUAL_UINT64(lc_sig_sqn_get(TERM[0].id.sqn), s.sqn);

    /* T0 takes another number (T4's) while the core has no location for
     * it (its LOC_UPDATE never arrived), so no LOC_CANCEL: the ACT_ACK names
     * another number than T0 is registered with, and the cell drops it */
    TEST_ASSERT_EQUAL_INT(0, SST.loc_del(SST.ctx, TERM[0].number));
    forget_events();
    activate_number(0, 0, TERM[4].number);
    TEST_ASSERT_TRUE(run_until_event(0, LC_SIG_EV_ACTIVATED, 3000));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    run_ms(5000);
    uint8_t got[LC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT(0, lc_sig_net_number(&CELL[0].c.net, TERM[0].tmid, got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM[4].number, got, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_UINT32(1, located(4));

    /* the same number again, with no location: the ACT_ACK can't be told
     * from an ACT_REQ answered again (a replay), so the registration stays
     * until the terminal registers with its new keys, as it does at once */
    TEST_ASSERT_EQUAL_INT(0, SST.loc_del(SST.ctx, TERM[4].number));
    uint8_t before[16];
    memcpy(before, sess_on(0, 0)->rand, 16);
    forget_events();
    activate_number(0, 0, TERM[4].number);
    TEST_ASSERT_TRUE(run_until_event(0, LC_SIG_EV_ACTIVATED, 3000));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    run_ms(5000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_FALSE(memcmp(before, sess_on(0, 0)->rand, 16) == 0); /* the new vector */
    TEST_ASSERT_EQUAL_UINT32(1, located(4));
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[4].number, &s));
    TEST_ASSERT_EQUAL_UINT64(lc_sig_sqn_get(TERM[0].id.sqn), s.sqn);
}

/* Review fix 1: T0's ACT_REQ, recorded on air, is played back after T0
 * registered, and again while it is in a call. The core answers it again
 * (the same token and terminal: the same number), so the cell leaves the
 * registration alone: T0 stays reachable, and its call goes on. */
static void test_a_replayed_act_req_leaves_the_terminal_registered(void)
{
    sim_world();
    registered_on(2, 0);
    TERM[0].rec = 1;
    activate_on(0, 0);
    TEST_ASSERT_TRUE(run_until_event(0, LC_SIG_EV_ACTIVATED, 3000));
    TERM[0].rec = 0;
    TEST_ASSERT_TRUE(TERM[0].nrp > 0);
    run_ms(8000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    unsigned acts = to_core[0][LC_CORE_ACT_FWD];
    replay_recorded(0);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT(acts + 1u, to_core[0][LC_CORE_ACT_FWD]); /* it reached the core */
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    forget_events();
    dial(2, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
    press(0, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(2));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));

    acts = to_core[0][LC_CORE_ACT_FWD];
    replay_recorded(0);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT(acts + 1u, to_core[0][LC_CORE_ACT_FWD]);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(2));
    TEST_ASSERT_EQUAL_INT(-1, ended(0));
    talk(2, "STILL HERE");
    run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("STILL HERE", TERM[0].app, 10);
}

/* §19 follow-up: LOC_CANCEL names the registration it cancels. T0 on cell
 * 1 (RAND A) goes to cell 2 and back. Cell 2's LOC_UPDATE (B) is held up
 * (its link cut after the vector, reported on reconnect); cell 1's for the
 * return (C) is lost on the way, and re-sent later. When B lands, the core
 * moves T0 to cell 2 and cancels cell 1's registration A - but cell 1 holds
 * C by now, and keeps it. C then moves T0 back, and cell 2 drops B. */
static void test_a_late_cancel_spares_a_newer_registration(void)
{
    sim_world();
    registered_on(2, 2);
    registered_on(0, 0);
    uint8_t a[16], b[16];
    memcpy(a, sess_on(0, 0)->rand, 16);

    TERM[0].cell = -1; /* to cell 2, which registers it while cut off */
    run_ms(2000);
    TERM[0].cell = 1;
    for (int k = 0; k < 100 && (sess_on(1, 0) == NULL || !sess_on(1, 0)->auth_pending); k++) frame();
    TEST_ASSERT_TRUE_MESSAGE(sess_on(1, 0)->auth_pending, "AUTH_REQ on its way");
    sim_disconnect(1);
    run_ms(3000);
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[1].c.net, TERM[0].tmid));
    memcpy(b, sess_on(1, 0)->rand, 16);

    TERM[0].cell = -1; /* back to cell 1, whose LOC_UPDATE is lost */
    run_ms(2000);
    TERM[0].cell = 0;
    forget_events();
    for (int k = 0; k < 100 && !sess_on(0, 0)->auth_pending; k++) frame();
    TEST_ASSERT_TRUE_MESSAGE(sess_on(0, 0)->auth_pending, "AUTH_REQ on its way");
    CELL[0].mute = 1;
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    CELL[0].mute = 0;
    TEST_ASSERT_FALSE(memcmp(a, sess_on(0, 0)->rand, 16) == 0); /* C */
    TEST_ASSERT_EQUAL_UINT32(1, located(0));                    /* the core still has A */

    sim_connect(1); /* B lands: newer than A */
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(2, located(0));
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, last_loc_cancel[0].u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(a, last_loc_cancel[0].u.loc_cancel.rand, 16);
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid)); /* C stays */
    TEST_ASSERT_NOT_NULL(reg_on(0, 0));

    wire_push(1, 0, CELL[0].link, &last_loc_update[0]); /* C, re-sent */
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(b, last_loc_cancel[1].u.loc_cancel.rand, 16);
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[1].c.net, TERM[0].tmid)); /* B dropped */
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    forget_events();
    dial(2, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* Review fix 4, the race a registration's drop of another session with its
 * number could lose: T0 (not registered on cell 1) holds a vector for its
 * number there when the number is re-activated on T3, which registers on
 * cell 1 at once; T0's answer to the older vector comes only then. The
 * session whose vector came later (T3) keeps the number; T0 is dropped. */
static void test_the_later_vector_keeps_the_number(void)
{
    sim_world();
    registered_on(2, 0);
    registered_on(0, 1); /* T0 on cell 2 */
    TERM[0].cell = -1;
    run_ms(2000);
    TERM[0].cell = 0; /* to cell 1: it asks for a vector there... */
    for (int k = 0; k < 100 && (sess_on(0, 0) == NULL || !sess_on(0, 0)->auth_pending); k++) frame();
    TEST_ASSERT_TRUE_MESSAGE(sess_on(0, 0)->auth_pending, "AUTH_REQ on its way");
    TERM[0].ul_lost = 1; /* ...and its answers are not heard for now */
    memcpy(TERM[3].number, TERM[0].number, LC_SIG_NUMBER_LEN);
    forget_events();
    activate_on(3, 0);
    TEST_ASSERT_TRUE(run_until_event(3, LC_SIG_EV_REGISTERED, 3000));
    TEST_ASSERT_TRUE(sess_on(0, 0)->auth_pending); /* T0's vector is still open */
    TERM[0].ul_lost = 0;
    run_ms(2000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED)); /* its answer matched, after T3's */
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[3].tmid));
    TEST_ASSERT_EQUAL_UINT32(1, located(3));
    forget_events();
    dial(2, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* The number T0 is registered with on cell 1 is re-activated on T3 while the
 * core has no location for T0 there (its LOC_UPDATE never arrived), so no
 * LOC_CANCEL comes. At cell 1, the ACT_ACK drops T0 (the same number); T0's
 * calls are refused, and a call to the number rings T3. */
static void test_reactivation_here_drops_a_registration_the_core_never_heard_of(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(2, 0);
    TEST_ASSERT_EQUAL_INT(0, SST.loc_del(SST.ctx, TERM[0].number)); /* a lost LOC_UPDATE */
    memcpy(TERM[3].number, TERM[0].number, LC_SIG_NUMBER_LEN);
    forget_events();
    activate_on(3, 0);
    TEST_ASSERT_TRUE(run_until_event(3, LC_SIG_EV_ACTIVATED, 3000));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    run_ms(5000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(3));
    TEST_ASSERT_EQUAL_UINT32(1, located(3));
    dial(0, "606-555-01232");
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_UNREACHABLE, ended(0));
    TEST_ASSERT_NULL(event(&TERM[2], LC_SIG_EV_INCOMING));
    dial(2, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* As above, but T3 activates and registers on cell 2, and only later comes
 * to cell 1, where T0 still holds the number: T3's registration there
 * drops T0, and a call to the number rings T3. */
static void test_a_registration_drops_a_stale_one_with_the_same_number(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(2, 0);
    TEST_ASSERT_EQUAL_INT(0, SST.loc_del(SST.ctx, TERM[0].number)); /* a lost LOC_UPDATE */
    memcpy(TERM[3].number, TERM[0].number, LC_SIG_NUMBER_LEN);
    registered_on(3, 1);
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid)); /* cell 1 heard nothing yet */
    TERM[3].cell = -1;
    run_ms(2000);
    TERM[3].cell = 0;
    forget_events();
    run_ms(8000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_UINT32(1, located(3));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    dial(2, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* Task 10 carry: a local call's MT leg also raises ALERTING and ANSWERED;
 * the cell switches it itself and tells the core nothing about it. */
static void test_a_local_call_sends_the_core_nothing(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(2, 0);
    dial(0, "606-555-01232");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[2], LC_SIG_EV_INCOMING));
    press(2, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    press(0, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NORMAL, ended(2));
    static const uint8_t call_types[] = { LC_CORE_CALL_ROUTE, LC_CORE_CALL_ALERT, LC_CORE_CALL_ANSWER,
                                          LC_CORE_CALL_RELEASE, LC_CORE_MEDIA };
    for (unsigned k = 0; k < sizeof(call_types); k++) TEST_ASSERT_EQUAL_UINT(0, to_core[0][call_types[k]]);
}

/* T0 on cell 1 calls T1 on cell 2: ring, answer, app data both ways,
 * hang-up by the caller; then again, hung up by the callee. */
static void test_cross_cell_call(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    const uint8_t *in = event(&TERM[1], LC_SIG_EV_INCOMING);
    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM[0].number, in + 5, LC_SIG_NUMBER_LEN); /* caller id across cells */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_RINGING_OUT, state(0));
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
    talk(0, "HELLO FROM CELL 1");
    run_ms(1000);
    TEST_ASSERT_EQUAL_UINT8(17, TERM[1].app_n);
    TEST_ASSERT_EQUAL_MEMORY("HELLO FROM CELL 1", TERM[1].app, 17);
    talk(1, "HI");
    run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("HI", TERM[0].app, 2);
    press(0, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NORMAL, ended(1));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));

    forget_events();
    dial(0, "+883-1-606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    press(1, LC_SIG_CMD_HANGUP); /* the callee hangs up this time */
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NORMAL, ended(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    const lc_core_cdr_t *c = &SMEM.d.cdr[(SMEM.d.ncdr - 1u) % LC_CORE_MEM_LOG];
    TEST_ASSERT_EQUAL_UINT32(1, c->cell_a);
    TEST_ASSERT_EQUAL_UINT32(2, c->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, c->answer);
}

/* Two terminals on one cell: switched there, as in plan 5; the core sees
 * no call. */
static void test_same_cell_call_stays_local(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(2, 0);
    unsigned cdrs = SMEM.d.ncdr;
    dial(0, "606-555-01232");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[2], LC_SIG_EV_INCOMING));
    press(2, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    talk(2, "LOCAL");
    run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("LOCAL", TERM[0].app, 5);
    press(0, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NORMAL, ended(2));
    TEST_ASSERT_EQUAL_UINT(cdrs, SMEM.d.ncdr);
}

static void test_reject_busy_unreachable_no_answer(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    registered_on(2, 1);

    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_REJECT);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_REJECTED, ended(0));

    forget_events(); /* T1 is in a local call with T2 on cell 2: busy */
    dial(2, "606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
    dial(0, "606-555-01231");
    run_ms(4000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_BUSY, ended(0));
    press(2, LC_SIG_CMD_HANGUP);
    run_ms(3000);

    forget_events();
    dial(0, "606-555-01239"); /* no such subscriber */
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_UNREACHABLE, ended(0));
    forget_events();
    dial(0, "606-555-01233"); /* a subscriber registered nowhere */
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_UNREACHABLE, ended(0));

    forget_events();
    dial(0, "606-555-01231");
    run_ms(65000); /* the callee's cell gives up after 60 s of ringing */
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NO_ANSWER, ended(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));
}

/* Review Focus 3: T0 and T1, on different cells, dial each other at the
 * same moment: each offer finds the callee busy placing its own call, and
 * both calls end busy; nobody is left ringing. */
static void test_both_dial_each_other_at_once(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    forget_events();
    dial(0, "606-555-01231");
    dial(1, "606-555-01230");
    run_ms(5000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_BUSY, ended(0));
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_BUSY, ended(1));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
}

static void test_echo_service(void)
{
    sim_world();
    registered_on(0, 2);
    forget_events();
    dial(0, "606-555-0100");
    run_ms(2000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_RINGING_OUT, state(0));
    run_ms(3000); /* it answers after 3 s */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    talk(0, "ECHO?");
    run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("ECHO?", TERM[0].app, 5);
    press(0, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
}

/* T0 and T1 in a call across cells 1 and 2. */
static void in_a_cross_cell_call(void)
{
    registered_on(0, 0);
    registered_on(1, 1);
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
}

/* §7.8: T0 leaves cell 1 while idle and attaches to cell 2; it registers
 * there by itself, cell 1 is told to drop it, and a call to T0 rings on
 * cell 2. */
static void test_idle_move_between_cells(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(2, 2);
    TERM[0].cell = -1; /* out of cell 1's coverage */
    run_ms(2000);
    TERM[0].cell = 1;  /* cell 2's beacon */
    forget_events();
    run_ms(8000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_UINT32(2, located(0));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid)); /* LOC_CANCEL(moved) */
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[1].c.net, TERM[0].tmid));
    dial(2, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* §7.1 step 4: the operator re-issues T0's number and another terminal
 * (T3, on cell 2) activates it while T0 is registered on cell 1: cell 1
 * drops T0, T0 can no longer call, and calls to the number reach T3. */
static void test_reactivation_on_a_new_terminal_elsewhere(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 2);
    memcpy(TERM[3].number, TERM[0].number, LC_SIG_NUMBER_LEN); /* T3 scans a new code for T0's number */
    registered_on(3, 1);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM[0].number, TERM[3].id.number, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(2, located(0));
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_UNREACHABLE, ended(0)); /* refused by its own cell */
    TEST_ASSERT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
    dial(1, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* §7.9 and "Done means": cell 2's process dies mid-call. The core sees its
 * link close and releases T0's leg at once (cause 5). When cell 2 is back
 * (a new boot), T1 registers again on re-attach and calls work again. */
static void test_cell_restart_mid_call(void)
{
    sim_world();
    in_a_cross_cell_call();
    sim_disconnect(1);
    CELL[1].up = 0; /* its beacon stops */
    run_ms(2000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT32(2, located(1)); /* the core keeps it until the cell's new boot */
    run_ms(8000);
    sim_cell_start(1);
    sim_connect(1);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(0, located(1)); /* HELLO with a new boot id purged cell 2 */
    run_ms(10000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));
    TEST_ASSERT_EQUAL_UINT32(2, located(1));
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
}

/* §7.10: the core restarts mid-call. Both cells lose their link and release
 * their legs (cause 5); the core comes back on its store, the cells
 * reconnect with their boot ids, and a new call connects without anyone
 * registering again. */
static void test_core_restart_mid_call(void)
{
    sim_world();
    in_a_cross_cell_call();
    for (int i = 0; i < SIM_CELLS; i++) sim_disconnect(i);
    run_ms(2000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(1));
    sim_core_start(); /* the same store: SQN, bindings, locations */
    for (int i = 0; i < SIM_CELLS; i++) sim_connect(i);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    TEST_ASSERT_EQUAL_UINT32(2, located(1));
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
}

/* §7.10: cell 2's backhaul is down. Its registered terminals still call
 * each other; calls into or out of the cell get cause 5; activation there
 * fails. Once the link is back, cross-cell calls work again.
 * "With the AV cache" (§9.2): plan 1 has none (plan 9), so what a cell holds
 * at the drop is the vector it was just given. T4, moving from cell 1 to
 * cell 2, has its vector there when the link drops: it registers offline,
 * and cell 2 reports it (LOC_UPDATE) when the link is back, which moves T4
 * from cell 1. (A terminal arriving with no vector held waits for the link:
 * test_registration_while_the_core_link_comes_up.) */
static void test_backhaul_outage_at_a_cell(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    registered_on(2, 1);
    registered_on(4, 0);
    TERM[4].cell = -1;
    run_ms(2000);
    TERM[4].cell = 1; /* to cell 2 */
    for (int k = 0; k < 100 && (sess_on(1, 4) == NULL || !sess_on(1, 4)->auth_pending); k++) frame();
    TEST_ASSERT_TRUE_MESSAGE(sess_on(1, 4)->auth_pending, "AUTH_REQ on its way");
    sim_disconnect(1);
    run_ms(3000);
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[1].c.net, TERM[4].tmid)); /* with the vector it held */
    TEST_ASSERT_EQUAL_UINT32(1, located(4));
    forget_events();
    dial(1, "606-555-01232");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[2], LC_SIG_EV_INCOMING)); /* local: no core needed */
    press(2, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
    press(1, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    forget_events();
    dial(1, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(1));
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    activate_on(3, 1);
    run_ms(8000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_ACT_FAILED));
    sim_connect(1);
    run_ms(1000);
    TEST_ASSERT_EQUAL_UINT32(2, located(4)); /* reported on HELLO_ACK */
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[4].tmid)); /* LOC_CANCEL(moved) */
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
}

/* The HSS is behind the terminal (a vector it already used, or a core
 * restored from an old copy): AUTH_FAIL(2) goes through the core as RESYNC
 * and the terminal registers without help. */
static void test_resync_through_the_core(void)
{
    sim_world();
    registered_on(0, 0);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    s.sqn = 0;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_put(SST.ctx, &s));
    lc_sig_sqn_put(TERM[0].id.sqn, 5000);
    const lc_sig_term_io_t io = TERM[0].t.io;
    lc_sig_term_init(&TERM[0].t, &io, &TERM[0].id, TERM[0].tmid, now); /* reboot: it registers again */
    forget_events();
    run_ms(10000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    TEST_ASSERT_EQUAL_UINT64(5001, s.sqn);
    TEST_ASSERT_EQUAL_UINT64(5001, lc_sig_sqn_get(TERM[0].id.sqn));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_RESYNC));
    TEST_ASSERT_EQUAL_UINT(1, to_core[0][LC_CORE_RESYNC]); /* cell 1 passed the AUTS on */
}

/* Audit records of event from cell_id, among those kept. */
static unsigned audits(uint8_t ev, uint32_t cell_id)
{
    unsigned n = 0, have = SMEM.d.naudit < LC_CORE_MEM_LOG ? SMEM.d.naudit : LC_CORE_MEM_LOG;
    for (unsigned k = 0; k < have; k++) {
        if (SMEM.d.audit[k].event == ev && SMEM.d.audit[k].cell_id == cell_id) n++;
    }
    return n;
}

/* A LOC_UPDATE as cell 3 (the rogue) sends it, straight to the core. */
static void rogue_claim(uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                        const uint8_t res[8])
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_UPDATE;
    m.u.loc_update.tmid = tmid;
    memcpy(m.u.loc_update.number, number, LC_SIG_NUMBER_LEN);
    memcpy(m.u.loc_update.rand, rand, 16);
    memcpy(m.u.loc_update.res, res, 8);
    wire_push(1, 2, CELL[2].link, &m);
    run_ms(500);
}

/* §8, §9.2 "a rogue cell claiming a location", §19: cell 3 tries to pull
 * T0 (registered on cell 1) to itself with everything it can get.
 * (1) It replays cell 1's claim (RAND and RES heard on the way): a vector
 * issued to another cell proves nothing from this one (AUTH_FAIL).
 * (2) It asks for a vector of its own for T0's TMID, heard on air: AV_REQ
 * answers it - the number, RAND, AUTN, HXRES, CK, IK, never XRES - and moves
 * nobody (§7.7); a LOC_UPDATE with anything it can compute from that
 * vector is refused (AUTH_FAIL): only the terminal can answer RAND. The same
 * claim under another terminal's TMID is refused as an "unproven stale
 * claim" (the number is not bound to it). Every attempt is audited against
 * cell 3; T0 stays on cell 1, and its calls ring there. */
static void test_rogue_cell_cannot_pull_a_subscriber(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_LOC_UPDATE, last_loc_update[0].type);
    wire_push(1, 2, CELL[2].link, &last_loc_update[0]);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    const lc_core_audit_t *a = lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(3, a->cell_id);
    TEST_ASSERT_EQUAL_UINT(1, audits(LC_CORE_AUDIT_AUTH_FAIL, 3));

    /* (2) a vector of its own for the TMID it heard */
    lc_core_msg_t q, r;
    memset(&q, 0, sizeof(q));
    q.type = LC_CORE_AV_REQ;
    q.u.av_req.req = 0x7777;
    q.u.av_req.tmid = TERM[0].tmid;
    q.u.av_req.count = 1;
    int from = NWIRE;
    lc_core_rx(&CORE, CELL[2].link, &q, now);
    const sim_frame_t *w = NULL;
    for (int k = from; k < NWIRE; k++) {
        if (!WIRE[k].to_core && WIRE[k].cell == 2) w = &WIRE[k];
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(w, "AV_RES to cell 3");
    TEST_ASSERT_EQUAL_INT(0, lc_core_decode(w->f, w->n, &r));
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_RES, r.type);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r.u.av_res.status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM[0].number, r.u.av_res.number, LC_SIG_NUMBER_LEN);
    const lc_core_av_t *v = &r.u.av_res.av[0];
    lc_core_av_issued_t row;
    TEST_ASSERT_EQUAL_INT(0, SST.av_get(SST.ctx, TERM[0].number, v->rand, &row));
    TEST_ASSERT_EQUAL_UINT32(3, row.cell_id);
    for (size_t k = 0; k + 8 <= w->n; k++) { /* no XRES on the wire */
        TEST_ASSERT_FALSE(memcmp(w->f + k, row.xres, 8) == 0);
    }
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0)); /* AV_REQ moves nobody */

    static const uint8_t zero[8] = { 0 };
    const uint8_t *guess[] = { v->hxres, v->hxres + 8, v->ck, v->ik, v->autn, v->rand, zero };
    const unsigned nguess = sizeof(guess) / sizeof(guess[0]);
    for (unsigned k = 0; k < nguess; k++) {
        rogue_claim(TERM[0].tmid, TERM[0].number, v->rand, guess[k]);
        TEST_ASSERT_EQUAL_UINT32(1, located(0));
    }
    TEST_ASSERT_EQUAL_UINT(1u + nguess, audits(LC_CORE_AUDIT_AUTH_FAIL, 3));
    a = lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM[0].number, a->number, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX32(TERM[0].tmid, a->tmid);
    TEST_ASSERT_EQUAL_INT(0, SST.av_get(SST.ctx, TERM[0].number, v->rand, &row));
    TEST_ASSERT_EQUAL_UINT8(0, row.confirmed);

    /* the number under T1's TMID: not the terminal it is bound to */
    unsigned cancels = audits(LC_CORE_AUDIT_LOC_CANCEL, 3);
    rogue_claim(TERM[1].tmid, TERM[0].number, v->rand, v->hxres);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    TEST_ASSERT_EQUAL_UINT32(2, located(1));
    TEST_ASSERT_EQUAL_UINT(cancels + 1u, audits(LC_CORE_AUDIT_LOC_CANCEL, 3));
    a = lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_EQUAL_UINT32(3, a->cell_id);
    TEST_ASSERT_NOT_NULL(strstr(a->detail, "unproven stale claim"));
    /* sent to the claimant only */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, last_loc_cancel[2].u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_UINT8(0, last_loc_cancel[0].type);
    TEST_ASSERT_EQUAL_UINT8(0, last_loc_cancel[1].type);
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[1].c.net, TERM[1].tmid));

    forget_events();
    dial(1, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* §19's floor: cell 3 once held T0 for real (a proven claim, RAND and RES
 * from the terminal). T0 moves to cell 1; cell 3 replays its own claim:
 * older than the location (SQN), refused, and cancelled back with its own
 * RAND. Then cell 1 restarts while T0 is switched off, and its new boot
 * purges T0's location. Replayed again, the claim is still refused: another
 * cell has proved a newer vector (a confirmed av_issued row), so the floor
 * outlives the location. The core audits each refusal as the LOC_CANCEL(moved)
 * it sends cell 3 (a proven claim, so not AUTH_FAIL); T0 is never located on
 * cell 3, and when it is back it registers on cell 1, where its calls ring. */
static void test_rogue_cell_cannot_replay_its_own_older_claim(void)
{
    sim_world();
    registered_on(1, 1);
    registered_on(0, 2);
    TEST_ASSERT_EQUAL_UINT32(3, located(0));
    const lc_core_msg_t own = last_loc_update[2];
    TEST_ASSERT_EQUAL_HEX32(TERM[0].tmid, own.u.loc_update.tmid);
    TERM[0].cell = -1;
    run_ms(2000);
    TERM[0].cell = 0; /* to cell 1 */
    run_ms(8000);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[2].c.net, TERM[0].tmid)); /* LOC_CANCEL(moved) */
    lc_core_av_issued_t row;
    TEST_ASSERT_EQUAL_INT(0, SST.av_get(SST.ctx, TERM[0].number, own.u.loc_update.rand, &row));
    TEST_ASSERT_EQUAL_UINT32(3, row.cell_id);
    TEST_ASSERT_EQUAL_UINT8(1, row.confirmed); /* a real, replayable proof */

    unsigned cancels = audits(LC_CORE_AUDIT_LOC_CANCEL, 3);
    memset(&last_loc_cancel[2], 0, sizeof(last_loc_cancel[2]));
    wire_push(1, 2, CELL[2].link, &own); /* while the location stands */
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, last_loc_cancel[2].u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(own.u.loc_update.rand, last_loc_cancel[2].u.loc_cancel.rand, 16);
    TEST_ASSERT_EQUAL_UINT(cancels + 1u, audits(LC_CORE_AUDIT_LOC_CANCEL, 3));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid)); /* cell 1 heard nothing */

    TERM[0].cell = -1; /* switched off */
    sim_disconnect(0);
    CELL[0].up = 0; /* cell 1's process dies */
    run_ms(2000);
    sim_cell_start(0); /* a new boot: the core purges cell 1's locations */
    sim_connect(0);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(0, located(0));
    memset(&last_loc_cancel[2], 0, sizeof(last_loc_cancel[2]));
    wire_push(1, 2, CELL[2].link, &own); /* with no location to be older than */
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(0, located(0));
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, last_loc_cancel[2].u.loc_cancel.cause);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(own.u.loc_update.rand, last_loc_cancel[2].u.loc_cancel.rand, 16);
    TEST_ASSERT_EQUAL_UINT(cancels + 2u, audits(LC_CORE_AUDIT_LOC_CANCEL, 3));
    const lc_core_audit_t *a = lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_EQUAL_UINT32(3, a->cell_id);
    TEST_ASSERT_EQUAL_STRING("cause 1", a->detail);
    TEST_ASSERT_EQUAL_UINT(1, audits(LC_CORE_AUDIT_REGISTER, 3)); /* only T0's real registration there */

    TERM[0].cell = 0; /* back on */
    forget_events();
    TEST_ASSERT_TRUE(run_until_event(0, LC_SIG_EV_REGISTERED, 10000));
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    forget_events();
    dial(1, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* §7.4 timers: the callee's cell never answers the offer (its frames to the
 * core are lost): the core gives up after 10 s, cause 5, on both legs. */
static void test_silent_callee_cell_times_out(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    CELL[1].mute = 1;
    forget_events();
    dial(0, "606-555-01231");
    run_ms(9000);
    TEST_ASSERT_EQUAL_INT(-1, ended(0));
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(1)); /* its ringing leg released too */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_activation_and_registration_through_the_core);
    RUN_TEST(test_registration_while_the_core_link_comes_up);
    RUN_TEST(test_an_offline_registration_is_reported_when_the_link_is_back);
    RUN_TEST(test_reactivation_drops_the_old_registration_first);
    RUN_TEST(test_reactivation_here_drops_a_registration_the_core_never_heard_of);
    RUN_TEST(test_a_registration_drops_a_stale_one_with_the_same_number);
    RUN_TEST(test_a_local_call_sends_the_core_nothing);
    RUN_TEST(test_a_replayed_act_req_leaves_the_terminal_registered);
    RUN_TEST(test_a_late_cancel_spares_a_newer_registration);
    RUN_TEST(test_the_later_vector_keeps_the_number);
    RUN_TEST(test_cross_cell_call);
    RUN_TEST(test_same_cell_call_stays_local);
    RUN_TEST(test_reject_busy_unreachable_no_answer);
    RUN_TEST(test_both_dial_each_other_at_once);
    RUN_TEST(test_echo_service);
    RUN_TEST(test_idle_move_between_cells);
    RUN_TEST(test_reactivation_on_a_new_terminal_elsewhere);
    RUN_TEST(test_cell_restart_mid_call);
    RUN_TEST(test_core_restart_mid_call);
    RUN_TEST(test_backhaul_outage_at_a_cell);
    RUN_TEST(test_resync_through_the_core);
    RUN_TEST(test_rogue_cell_cannot_pull_a_subscriber);
    RUN_TEST(test_rogue_cell_cannot_replay_its_own_older_claim);
    RUN_TEST(test_silent_callee_cell_times_out);
    return UNITY_END();
}
