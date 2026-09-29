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
 * sends LOC_CANCEL(reactivated) and then ACT_RES; the cell drops the old
 * registration without losing the open activation, so the terminal is
 * activated, and it registers again with the new keys. */
static void test_reactivation_drops_the_old_registration_first(void)
{
    sim_world();
    registered_on(0, 0);
    forget_events();
    activate_on(0, 0);
    TEST_ASSERT_TRUE(run_until_event(0, LC_SIG_EV_ACTIVATED, 3000));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid)); /* dropped before the ACT_ACK */
    TEST_ASSERT_EQUAL_UINT32(0, located(0));
    const lc_core_audit_t *a = lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(1, a->cell_id);
    run_ms(5000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    TEST_ASSERT_EQUAL_UINT64(lc_sig_sqn_get(TERM[0].id.sqn), s.sqn);

    /* again, with no location at the core (its LOC_UPDATE never arrived), so
     * no LOC_CANCEL: the cell drops the activating terminal's registration
     * itself */
    TEST_ASSERT_EQUAL_INT(0, SST.loc_del(SST.ctx, TERM[0].number));
    forget_events();
    activate_on(0, 0);
    TEST_ASSERT_TRUE(run_until_event(0, LC_SIG_EV_ACTIVATED, 3000));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    run_ms(5000);
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
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
    return UNITY_END();
}
