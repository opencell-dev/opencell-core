/* Visiting subscribers (OCSS spec 2026-11-01 §4, §8): two cores, real cells
 * (oc_cell) and terminals (oc_sig_term). A terminal on a core-1 cell with a
 * core-2 number activates, registers, places and receives calls, and the
 * reverse; the home core keeps the keys, the location and the CDRs. */
#include "net_sim2.h"

void setUp(void) {}
void tearDown(void) {}

/* Terminal 1 (+883 1 503 ..., homed on core 2) on cell 0 (core 1). */
static void test_a_visitor_activates_and_registers_through_its_home(void)
{
    s2_world();
    s2_registered_on(1, 0);
    oc_core_loc_t l;
    TEST_ASSERT_TRUE(s2_loc(1, 1, &l)); /* the home core: on core 1's cell 1 */
    TEST_ASSERT_EQUAL_UINT16(1, l.core);
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_UINT32(TERM2[1].tmid, l.tmid);
    TEST_ASSERT_TRUE(s2_loc(0, 1, &l)); /* the serving core's visitor row */
    TEST_ASSERT_EQUAL_UINT16(0, l.core);
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    oc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, CORE2[0].st.sub_get(CORE2[0].st.ctx, TERM2[1].number, &s)); /* no keys on core 1 */
    TEST_ASSERT_EQUAL_INT(0, CORE2[1].st.sub_get(CORE2[1].st.ctx, TERM2[1].number, &s));
    TEST_ASSERT_TRUE(s.activated);
    TEST_ASSERT_EQUAL_UINT32(TERM2[1].tmid, s.tmid);
    TEST_ASSERT_TRUE(s.sqn >= 1); /* the SQN stepped on the home core */
    TEST_ASSERT_TRUE(ocss_sent[0][OC_OCSS_ACT_RELAY] >= 1);
    TEST_ASSERT_TRUE(ocss_sent[0][OC_OCSS_AV_RELAY] >= 1);
    TEST_ASSERT_TRUE(ocss_sent[0][OC_OCSS_LOC_UPDATE] >= 1);
    TEST_ASSERT_TRUE(ocss_sent[1][OC_OCSS_LOC_ACK] >= 1);

    /* a local subscriber on the same core still works as before */
    s2_registered_on(0, 1);
    TEST_ASSERT_TRUE(s2_loc(0, 0, &l));
    TEST_ASSERT_EQUAL_UINT16(0, l.core);
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
}

static void call_and_talk(int from, int to, const char *dialled)
{
    s2_forget();
    s2_dial(from, dialled);
    s2_run_ms(3000);
    const uint8_t *in = s2_event(&TERM2[to], OC_SIG_EV_INCOMING);
    TEST_ASSERT_NOT_NULL_MESSAGE(in, dialled);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM2[from].number, in + 5, OC_SIG_NUMBER_LEN);
    s2_press(to, OC_SIG_CMD_ANSWER);
    s2_run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_IN_CALL, s2_state(from));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_IN_CALL, s2_state(to));
    s2_talk(from, "OVER");
    s2_run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("OVER", TERM2[to].app, 4);
    s2_talk(to, "BACK");
    s2_run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("BACK", TERM2[from].app, 4);
    s2_press(from, OC_SIG_CMD_HANGUP);
    s2_run_ms(3000);
    TEST_ASSERT_EQUAL_INT(OC_SIG_CAUSE_NORMAL, s2_ended(to));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, s2_state(from));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, s2_state(to));
}

/* Calls to and from the visitor on core 1: LOCATE at its home, then core 1
 * switches the call itself; the home core gets a CDR copy. */
static void test_a_visitor_calls_and_is_called(void)
{
    s2_world();
    s2_registered_on(1, 0); /* core-2 number on core 1's cell 0 */
    s2_registered_on(0, 1); /* core-1 number on core 1's cell 1 */
    unsigned cdr2 = CORE2[1].mem.d.ncdr;

    call_and_talk(0, 1, "+883-1-503-555-01231"); /* local caller -> visitor: its visitor row here */
    TEST_ASSERT_EQUAL_UINT(0, ocss_sent[0][OC_OCSS_LOCATE]);
    TEST_ASSERT_EQUAL_UINT(0, ocss_sent[0][OC_OCSS_CALL_SETUP]); /* the home is not in the call */
    const oc_core_cdr_t *c = s2_last_cdr(0);
    TEST_ASSERT_EQUAL_UINT32(2, c->cell_a);
    TEST_ASSERT_EQUAL_UINT32(1, c->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, c->answer);
    TEST_ASSERT_EQUAL_UINT(cdr2 + 1u, CORE2[1].mem.d.ncdr); /* the copy at the visitor's home */
    c = s2_last_cdr(1);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM2[0].number, c->caller, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM2[1].number, c->called, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_NOT_EQUAL(0, c->answer);

    call_and_talk(1, 0, "+883-1-606-555-01230"); /* visitor -> local */
    TEST_ASSERT_EQUAL_UINT(cdr2 + 2u, CORE2[1].mem.d.ncdr);

    /* a core-2 subscriber at home, called from core 1: LOCATE, then the call
     * goes to core 2 */
    s2_registered_on(3, 2);
    call_and_talk(0, 3, "+883-1-503-555-01233");
    TEST_ASSERT_TRUE(ocss_sent[0][OC_OCSS_LOCATE] >= 1);
    TEST_ASSERT_TRUE(ocss_sent[0][OC_OCSS_CALL_SETUP] >= 1);
    call_and_talk(1, 3, "+883-1-503-555-01233"); /* the visitor calls its home core's subscriber */

    /* the visitor calls its home core's echo service over OCSS */
    s2_forget();
    s2_dial(1, "+883-1-503-555-00100");
    s2_run_ms(6000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_IN_CALL, s2_state(1));
    s2_talk(1, "ECHO");
    s2_run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("ECHO", TERM2[1].app, 4);
    s2_press(1, OC_SIG_CMD_HANGUP);
    s2_run_ms(2000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, s2_state(1));
}

/* A core-1 number on core 2's cell, and a core-2 local subscriber there:
 * the visitor is called from core 1 (its home sends the call straight to
 * core 2) and from core 2 (a visitor row there), and calls out. */
static void test_the_reverse_a_core1_number_on_core2(void)
{
    s2_world();
    s2_registered_on(2, 2); /* core-1 number on core 2's cell */
    s2_registered_on(3, 2); /* core-2 number, home */
    s2_registered_on(0, 0); /* core-1 number, home */
    oc_core_loc_t l;
    TEST_ASSERT_TRUE(s2_loc(0, 2, &l));
    TEST_ASSERT_EQUAL_UINT16(2, l.core);
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id); /* core 2's cell 1, not core 1's cell 1 */

    call_and_talk(0, 2, "+883-1-606-555-01232"); /* home caller -> visitor on core 2 */
    call_and_talk(3, 2, "+883-1-606-555-01232"); /* same-cell call: the cell switches it */
    call_and_talk(2, 0, "+883-1-606-555-01230"); /* visitor -> its home core's subscriber */
    call_and_talk(2, 3, "+883-1-503-555-01233");
}

/* The visitor moves between core 1's cells, and its home disables it. */
static void test_a_visitor_moves_and_is_disabled(void)
{
    s2_world();
    s2_registered_on(1, 0);
    TERM2[1].cell = -1; /* out of cell 0's coverage */
    s2_run_ms(2000);
    TERM2[1].cell = 1; /* cell 1's beacon (same core) */
    s2_run_ms(8000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, s2_state(1));
    oc_core_loc_t l;
    TEST_ASSERT_TRUE(s2_loc(1, 1, &l));
    TEST_ASSERT_EQUAL_UINT16(1, l.core);
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
    TEST_ASSERT_TRUE(s2_loc(0, 1, &l));
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
    TEST_ASSERT_TRUE(ocss_sent[1][OC_OCSS_LOC_CANCEL] >= 1); /* the old registration on cell 0 */
    TEST_ASSERT_FALSE(oc_sig_net_registered(&CELL2[0].c.net, TERM2[1].tmid));
    TEST_ASSERT_TRUE(oc_sig_net_registered(&CELL2[1].c.net, TERM2[1].tmid));

    TEST_ASSERT_EQUAL_INT(0, oc_core_sub_disable(&CORE2[1].k, TERM2[1].number, now2));
    s2_run_ms(1000);
    TEST_ASSERT_FALSE(s2_loc(0, 1, &l)); /* the visitor row went with the cancel */
    TEST_ASSERT_FALSE(s2_loc(1, 1, &l));
    TEST_ASSERT_FALSE(oc_sig_net_registered(&CELL2[1].c.net, TERM2[1].tmid)); /* the cell dropped it */
}

/* Without the link to its home, a visitor can't be reached (cause 5), and a
 * peer can't cancel a number it is not home for. */
static void test_refusals(void)
{
    s2_world();
    s2_registered_on(0, 1);
    s2_forget();
    s2_dial(0, "+883-1-503-555-01233"); /* not registered anywhere */
    s2_run_ms(3000);
    TEST_ASSERT_EQUAL_INT(OC_SIG_CAUSE_UNREACHABLE, s2_ended(0));

    s2_peer_link_down();
    s2_forget();
    s2_dial(0, "+883-1-503-555-01233");
    s2_run_ms(3000);
    TEST_ASSERT_EQUAL_INT(OC_SIG_CAUSE_NET_FAILURE, s2_ended(0));
    s2_peer_link_up();
    s2_run_ms(500);

    /* core 2 cancels core 1's own subscriber: refused, the terminal stays */
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_LOC_CANCEL;
    m.u.peer_cancel.tmid = TERM2[0].tmid;
    m.u.peer_cancel.cause = OC_CORE_CANCEL_DISABLED;
    memcpy(m.u.peer_cancel.number, TERM2[0].number, OC_SIG_NUMBER_LEN);
    m.u.peer_cancel.cell = 2;
    oc_core_peer_rx(&CORE2[0].k, S2_PEER_LINK(0), &m, now2);
    s2_run_ms(1000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, s2_state(0));

    /* a peer's LOC_UPDATE with a RES no vector backs: refused */
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_LOC_UPDATE;
    m.u.peer_loc.req = 77;
    m.u.peer_loc.tmid = TERM2[1].tmid;
    memcpy(m.u.peer_loc.number, TERM2[1].number, OC_SIG_NUMBER_LEN);
    m.u.peer_loc.cell = 9;
    m.u.peer_loc.life_s = 3600;
    oc_core_peer_rx(&CORE2[1].k, S2_PEER_LINK(1), &m, now2);
    oc_core_loc_t l;
    TEST_ASSERT_FALSE(s2_loc(1, 1, &l));
}

/* A terminal re-activated with a core-2 number lets go of its core-1 one:
 * core 1 hears TMID_BOUND and unbinds it, and its vectors come from core 2. */
static void test_a_terminal_moves_to_a_number_of_the_other_core(void)
{
    s2_world();
    s2_registered_on(0, 0); /* terminal 0 with its core-1 number */
    s2_activate(0, 0, TERM2[1].number, 1); /* now terminal 1's core-2 number on terminal 0 */
    s2_run_ms(10000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, s2_state(0));
    oc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, CORE2[0].st.sub_get(CORE2[0].st.ctx, TERM2[0].number, &s));
    TEST_ASSERT_FALSE(s.activated); /* unbound on core 1 */
    TEST_ASSERT_EQUAL_INT(0, CORE2[1].st.sub_get(CORE2[1].st.ctx, TERM2[1].number, &s));
    TEST_ASSERT_EQUAL_UINT32(TERM2[0].tmid, s.tmid);
    oc_core_loc_t l;
    TEST_ASSERT_FALSE(s2_loc(0, 0, &l));
    TEST_ASSERT_TRUE(s2_loc(1, 1, &l));
    TEST_ASSERT_EQUAL_UINT16(1, l.core);
}

/* The serving core forgot the TMID (a restart empties its cache): it asks
 * every peer for vectors and the home answers (OCSS spec §4.1 rule 3); a
 * LOCATE that gets no answer ends the call with cause 5. */
static void test_an_unknown_tmid_and_a_lost_locate(void)
{
    s2_world();
    s2_registered_on(1, 0);
    s2_registered_on(0, 1);
    s2_registered_on(3, 2);
    memset(CORE2[0].k.tmids, 0, sizeof(CORE2[0].k.tmids));
    unsigned av = ocss_sent[0][OC_OCSS_AV_RELAY];
    TERM2[1].cell = -1;
    s2_run_ms(2000);
    TERM2[1].cell = 1;
    s2_forget();
    s2_run_ms(8000);
    TEST_ASSERT_NOT_NULL(s2_event(&TERM2[1], OC_SIG_EV_REGISTERED));
    TEST_ASSERT_TRUE(ocss_sent[0][OC_OCSS_AV_RELAY] > av);

    CUT2 = 1; /* the link stays up but its frames are lost */
    s2_forget();
    s2_dial(0, "+883-1-503-555-01233");
    s2_run_ms(5000);
    TEST_ASSERT_EQUAL_INT(OC_SIG_CAUSE_NET_FAILURE, s2_ended(0));
    CUT2 = 0;
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a_visitor_activates_and_registers_through_its_home);
    RUN_TEST(test_a_visitor_calls_and_is_called);
    RUN_TEST(test_the_reverse_a_core1_number_on_core2);
    RUN_TEST(test_a_visitor_moves_and_is_disabled);
    RUN_TEST(test_refusals);
    RUN_TEST(test_a_terminal_moves_to_a_number_of_the_other_core);
    RUN_TEST(test_an_unknown_tmid_and_a_lost_locate);
    return UNITY_END();
}
