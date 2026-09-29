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
    return UNITY_END();
}
