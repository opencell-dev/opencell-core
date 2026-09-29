/* The switch (network-core spec §7.4-7.6): a call between two cells, relay
 * of alert, answer, media and release, the refusals and their causes, the
 * setup timer, the echo service, a cell that goes away, and the CDRs. */
#include "unity.h"

#include "core_fixture.h"

void setUp(void) {}
void tearDown(void) {}

#define TA 0x0000aaaau
#define TB 0x0000bbbbu
#define LEG 7u

static uint8_t NA[LC_SIG_NUMBER_LEN], NB[LC_SIG_NUMBER_LEN], ECHO[LC_SIG_NUMBER_LEN];

static void subscriber(const uint8_t n[LC_SIG_NUMBER_LEN], uint32_t tmid, uint32_t cell)
{
    uint8_t got[LC_SIG_NUMBER_LEN];
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, n, got));
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, n, &s));
    s.activated = 1;
    s.tmid = tmid;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    lc_core_loc_t l = { { 0 }, cell, tmid, UNIX0 + 3600u, 0, { 0 } };
    memcpy(l.number, n, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

/* A on cell 1 (link 10), B on cell 2 (link 20). */
static void sw_world(void)
{
    core_world();
    number("+883160655501234", NA);
    number("+883160655501235", NB);
    number(ECHO_NUM, ECHO);
    hello(10, 1, 1); /* first: a cell's first HELLO is a new boot, which purges its locations */
    hello(20, 2, 1);
    subscriber(NA, TA, 1);
    subscriber(NB, TB, 2);
}

static void route(uint32_t link, uint32_t leg, const uint8_t caller[], const uint8_t called[])
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = leg;
    memcpy(m.u.call_route.caller, caller, LC_SIG_NUMBER_LEN);
    memcpy(m.u.call_route.called, called, LC_SIG_NUMBER_LEN);
    rx(link, &m);
}

static void call_msg(uint32_t link, uint8_t type, uint32_t ref, uint8_t cause)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = ref;
    m.u.call.cause = cause;
    rx(link, &m);
}

static void media(uint32_t link, uint32_t ref, const char *s)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_MEDIA;
    m.u.media.ref = ref;
    m.u.media.seq = 5;
    m.u.media.len = (uint8_t)strlen(s);
    memcpy(m.u.media.data, s, m.u.media.len);
    rx(link, &m);
}

static const lc_core_cdr_t *last_cdr(void)
{
    TEST_ASSERT_TRUE(MEM.d.ncdr > 0);
    return &MEM.d.cdr[(MEM.d.ncdr - 1u) % LC_CORE_MEM_LOG];
}

/* Routes A -> B and returns the core's ref for B's leg. */
static uint32_t offered(void)
{
    int from = NSENT;
    route(10, LEG, NA, NB);
    const lc_core_msg_t *o = sent_since(from, 20, LC_CORE_CALL_OFFER);
    TEST_ASSERT_NOT_NULL(o);
    TEST_ASSERT_TRUE((o->u.call_offer.call_ref & LC_CORE_REF_CORE) != 0);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NB, o->u.call_offer.callee, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NA, o->u.call_offer.caller, LC_SIG_NUMBER_LEN);
    return o->u.call_offer.call_ref;
}

static void test_cross_cell_call_relays_both_ways(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(20, LC_CORE_CALL_ALERT, ref, 0);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ALERT)->u.call.ref);
    media(10, LEG, "EARLY"); /* no media before the answer */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_MEDIA));
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ANSWER)->u.call.ref);
    media(10, LEG, "UP");
    const lc_core_msg_t *d = sent_since(from, 20, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(ref, d->u.media.ref);
    TEST_ASSERT_EQUAL_UINT16(5, d->u.media.seq);
    TEST_ASSERT_EQUAL_MEMORY("UP", d->u.media.data, 2);
    media(20, ref, "DOWN");
    d = sent_since(from, 10, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
    TEST_ASSERT_EQUAL_MEMORY("DOWN", d->u.media.data, 4);
    call_msg(20, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_NORMAL); /* B hangs up */
    const lc_core_msg_t *r = sent_since(from, 10, LC_CORE_CALL_RELEASE);
    TEST_ASSERT_EQUAL_UINT32(LEG, r->u.call.ref);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NORMAL, r->u.call.cause);
    const lc_core_cdr_t *c = last_cdr();
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NA, c->caller, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NB, c->called, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_UINT32(1, c->cell_a);
    TEST_ASSERT_EQUAL_UINT32(2, c->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, c->answer);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NORMAL, c->cause);
    from = NSENT;
    media(10, LEG, "LATE"); /* the call is gone */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_MEDIA));
}

static void test_caller_hangs_up_and_callee_refuses(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(10, LC_CORE_CALL_RELEASE, LEG, LC_SIG_CAUSE_NORMAL); /* A gives up while it rings */
    TEST_ASSERT_EQUAL_UINT32(ref, sent_since(from, 20, LC_CORE_CALL_RELEASE)->u.call.ref);
    TEST_ASSERT_EQUAL_UINT32(0, last_cdr()->answer);

    static const uint8_t causes[] = { LC_SIG_CAUSE_BUSY, LC_SIG_CAUSE_REJECTED, LC_SIG_CAUSE_NO_ANSWER,
                                      LC_SIG_CAUSE_UNREACHABLE };
    for (unsigned i = 0; i < sizeof(causes); i++) { /* cell B's answer reaches A unchanged */
        ref = offered();
        from = NSENT;
        call_msg(20, LC_CORE_CALL_RELEASE, ref, causes[i]);
        TEST_ASSERT_EQUAL_UINT8(causes[i], sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
        TEST_ASSERT_EQUAL_UINT8(causes[i], last_cdr()->cause);
    }
}

static uint8_t refused(const uint8_t caller[], const uint8_t called[])
{
    int from = NSENT;
    route(10, LEG, caller, called);
    const lc_core_msg_t *r = sent_since(from, 10, LC_CORE_CALL_RELEASE);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT32(LEG, r->u.call.ref);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
    TEST_ASSERT_EQUAL_UINT8(r->u.call.cause, last_cdr()->cause); /* every attempt has its CDR */
    return r->u.call.cause;
}

static void test_refusals_and_their_causes(void)
{
    uint8_t n[LC_SIG_NUMBER_LEN];
    sw_world();
    number("+883160655509999", n);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, n)); /* no such subscriber */
    number("+883442079460000", n);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, n)); /* no route */
    TEST_ASSERT_EQUAL_INT(0, ST.loc_del(ST.ctx, NB));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, NB)); /* registered nowhere */
    lc_core_loc_t l = { { 0 }, 2, TB, UNIX0 + 10u, 0, { 0 } };
    memcpy(l.number, NB, LC_SIG_NUMBER_LEN);
    ST.loc_put(ST.ctx, &l);
    NOW += 20000000u;
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, NB)); /* its location expired */
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, NB, &l));
    l.expires = UNIX0 + 3600u;
    ST.loc_put(ST.ctx, &l);
    lc_core_link_down(&K, 20, NOW);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, refused(NA, NB)); /* B's cell is cut off */
    hello(20, 2, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, refused(NB, NA)); /* cell 1 calling as B */
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, NB, NOW));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, NB)); /* disabled */
}

/* §7.4 timers: no alert or release from the callee's cell in 10 s. */
static void test_setup_times_out_after_10_s(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    advance(LC_CORE_SETUP_US - 1000000u);
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_RELEASE));
    call_msg(10, LC_CORE_PING, 0, 0); /* keep the links alive */
    call_msg(20, LC_CORE_PING, 0, 0);
    advance(1000000u);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
    const lc_core_msg_t *b = sent_since(from, 20, LC_CORE_CALL_RELEASE);
    TEST_ASSERT_EQUAL_UINT32(ref, b->u.call.ref);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, b->u.call.cause);

    ref = offered(); /* an alert stops the timer: ringing is the callee cell's 60 s */
    call_msg(20, LC_CORE_CALL_ALERT, ref, 0);
    from = NSENT;
    for (int i = 0; i < 4; i++) {
        advance(4000000u);
        call_msg(10, LC_CORE_PING, 0, 0);
        call_msg(20, LC_CORE_PING, 0, 0);
    }
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_RELEASE));
}

static void test_echo_service_rings_answers_and_echoes(void)
{
    sw_world();
    int from = NSENT;
    route(10, LEG, NA, ECHO);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ALERT)->u.call.ref);
    advance(LC_CORE_ECHO_US - 1u);
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_ANSWER));
    advance(1u);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ANSWER)->u.call.ref);
    media(10, LEG, "HELLO");
    const lc_core_msg_t *d = sent_since(from, 10, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
    TEST_ASSERT_EQUAL_MEMORY("HELLO", d->u.media.data, 5);
    call_msg(10, LC_CORE_CALL_RELEASE, LEG, LC_SIG_CAUSE_NORMAL);
    TEST_ASSERT_EQUAL_UINT32(0, last_cdr()->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, last_cdr()->answer);
}

/* A cell's link goes, or it comes back from a restart: every call with a
 * leg on it ends, and the other side hears cause 5 at once. */
static void test_a_cell_going_releases_its_calls(void)
{
    sw_world();
    uint32_t ref = offered();
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0);
    int from = NSENT;
    lc_core_link_down(&K, 20, NOW);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, last_cdr()->cause);

    hello(20, 2, 1);
    ref = offered();
    from = NSENT;
    hello(30, 1, 2); /* cell 1 restarted: a new boot on a new link */
    TEST_ASSERT_EQUAL_UINT32(ref, sent_since(from, 20, LC_CORE_CALL_RELEASE)->u.call.ref);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, NA, &l)); /* and cell 1's registrations are gone */
}

/* Review Focus 2: the callee's cell has no session for it any more (it
 * moved, or the cell restarted unnoticed): cause 4, and the stale location
 * goes, so the next call is refused at once instead of offered again. */
static void test_stale_location_is_dropped(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(20, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_UNREACHABLE);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, NB, &l));
    from = NSENT;
    route(10, LEG + 1u, NA, NB);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
}

/* Review Focus 5: a CALL_ROUTE repeated for a leg already routed (a
 * duplicated frame) makes no second offer and no second call. */
static void test_repeated_route_is_ignored(void)
{
    sw_world();
    offered();
    int from = NSENT;
    route(10, LEG, NA, NB);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_RELEASE));
    unsigned used = 0;
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) used += K.calls[i].used ? 1u : 0u;
    TEST_ASSERT_EQUAL_UINT(1, used);
    route(10, LC_CORE_REF_CORE | 5u, NA, NB); /* not a ref a cell may use */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
}

/* Follow-up review: a cell that resends HELLO on the SAME link with a new
 * boot_id (the process restarted, the link itself did not drop) takes a
 * different branch in lc_core.c's on_hello (old == l) than a reconnect on a
 * new link, but must still release every call with a leg on that cell. */
static void test_new_boot_on_same_link_releases_its_calls(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    hello(10, 1, 2); /* same link 10, cell 1, a new boot_id */
    const lc_core_msg_t *r = sent_since(from, 20, LC_CORE_CALL_RELEASE);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT32(ref, r->u.call.ref);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, r->u.call.cause);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, NA, &l)); /* cell 1's registrations are purged too */
}

/* Follow-up review: caller and callee both land on the same cell. The core
 * still runs two legs on that one cell with two different refs, and every
 * relay must carry the far leg's own ref, not the near one's. */
static void test_same_cell_both_legs_relay_with_ref_split(void)
{
    uint8_t nc[LC_SIG_NUMBER_LEN];
    sw_world();
    number("+883160655501236", nc);
    subscriber(nc, 0xccccu, 1); /* C, also on cell 1 */
    int from = NSENT;
    route(10, LEG, NA, nc);
    const lc_core_msg_t *o = sent_since(from, 10, LC_CORE_CALL_OFFER);
    TEST_ASSERT_NOT_NULL(o);
    uint32_t ref = o->u.call_offer.call_ref;
    TEST_ASSERT_NOT_EQUAL(LEG, ref);
    call_msg(10, LC_CORE_CALL_ALERT, ref, 0);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ALERT)->u.call.ref);
    call_msg(10, LC_CORE_CALL_ANSWER, ref, 0);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ANSWER)->u.call.ref);
    media(10, LEG, "HI"); /* A's leg -> relayed with C's ref */
    const lc_core_msg_t *d = sent_since(from, 10, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(ref, d->u.media.ref);
    media(10, ref, "YO"); /* C's leg -> relayed with A's ref */
    d = sent_since(from, 10, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
    call_msg(10, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_NORMAL); /* C hangs up */
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.ref);
}

/* Follow-up review: the callee's cell may answer without ever alerting
 * (e.g. auto-answer). The ROUTING -> ACTIVE transition does not require
 * having passed through ALERTING, and the setup timer must not still fire. */
static void test_answer_without_prior_alert(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0); /* no ALERT first */
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ANSWER)->u.call.ref);
    advance(LC_CORE_SETUP_US);
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_RELEASE)); /* answered: the setup timer no longer applies */
}

/* Follow-up review: ALERT/ANSWER carrying the caller's own leg ref (instead
 * of the callee's) is not a message this switch accepts from that leg: it
 * must be ignored, not misrouted or treated as the callee answering. */
static void test_alert_answer_from_leg_a_ignored(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(10, LC_CORE_CALL_ALERT, LEG, 0); /* A is not the callee's leg */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_ALERT));
    call_msg(10, LC_CORE_CALL_ANSWER, LEG, 0); /* likewise */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_ANSWER));
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0); /* the real answer, from B, still works */
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ANSWER)->u.call.ref);
}

/* Follow-up review: the caller gives up while the echo service is still
 * ringing. The call must end at once, with no late ANSWER from the echo
 * timer once its due time passes. */
static void test_caller_hangs_up_while_echo_rings(void)
{
    sw_world();
    int from = NSENT;
    route(10, LEG, NA, ECHO);
    TEST_ASSERT_NOT_NULL(sent_since(from, 10, LC_CORE_CALL_ALERT));
    call_msg(10, LC_CORE_CALL_RELEASE, LEG, LC_SIG_CAUSE_NORMAL);
    const lc_core_cdr_t *c = last_cdr();
    TEST_ASSERT_EQUAL_UINT32(0, c->cell_b);
    TEST_ASSERT_EQUAL_UINT32(0, c->answer); /* never answered */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NORMAL, c->cause);
    from = NSENT;
    advance(LC_CORE_ECHO_US); /* the call is gone: no late ANSWER from the echo timer */
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_ANSWER));
}

/* Follow-up review: exactly one CDR per ended call, both when a cell going
 * away ends it and when the setup timer ends it. */
static void test_cdr_count_delta_is_exactly_one(void)
{
    sw_world();
    uint32_t ref = offered();
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0);
    unsigned n0 = MEM.d.ncdr;
    lc_core_link_down(&K, 20, NOW);
    TEST_ASSERT_EQUAL_UINT(n0 + 1u, MEM.d.ncdr); /* the one call with a leg on cell 2 */

    hello(20, 2, 1);
    offered();
    n0 = MEM.d.ncdr;
    advance(LC_CORE_SETUP_US);
    TEST_ASSERT_EQUAL_UINT(n0 + 1u, MEM.d.ncdr); /* the one call that timed out */
}

/* Follow-up review: a failed CDR write must not stop the release from
 * reaching the other leg or leave the call slot stuck as used. */
static int fail_cdr(void *ctx, const lc_core_cdr_t *c)
{
    (void)ctx;
    (void)c;
    return -1;
}

static void test_cdr_add_failure_does_not_break_release(void)
{
    sw_world();
    uint32_t ref = offered();
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0);
    int from = NSENT;
    int (*real_cdr_add)(void *, const lc_core_cdr_t *) = K.st.cdr_add;
    K.st.cdr_add = fail_cdr;
    call_msg(20, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_NORMAL);
    K.st.cdr_add = real_cdr_add;
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.ref);
    unsigned used = 0;
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) used += K.calls[i].used ? 1u : 0u;
    TEST_ASSERT_EQUAL_UINT(0, used); /* the slot was freed despite the CDR write failing */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cross_cell_call_relays_both_ways);
    RUN_TEST(test_caller_hangs_up_and_callee_refuses);
    RUN_TEST(test_refusals_and_their_causes);
    RUN_TEST(test_setup_times_out_after_10_s);
    RUN_TEST(test_echo_service_rings_answers_and_echoes);
    RUN_TEST(test_a_cell_going_releases_its_calls);
    RUN_TEST(test_stale_location_is_dropped);
    RUN_TEST(test_repeated_route_is_ignored);
    RUN_TEST(test_new_boot_on_same_link_releases_its_calls);
    RUN_TEST(test_same_cell_both_legs_relay_with_ref_split);
    RUN_TEST(test_answer_without_prior_alert);
    RUN_TEST(test_alert_answer_from_leg_a_ignored);
    RUN_TEST(test_caller_hangs_up_while_echo_rings);
    RUN_TEST(test_cdr_count_delta_is_exactly_one);
    RUN_TEST(test_cdr_add_failure_does_not_break_release);
    return UNITY_END();
}
