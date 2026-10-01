/* OCSS between two cores (core test services spec §6): HELLO, liveness,
 * and the relay: a cell on core 1 calls core 2's echo and playback
 * services, and numbers in core 2's block, over the link; the causes when
 * core 2 can't be reached or refuses; a lost link ends its calls; core 2
 * never sends a call on. Core 1 is home for +883 1 606 and routes +883 1
 * 503 to core 2, which is home for it; both on in-memory stores. Frames
 * between the cores are queued and delivered by pump(), never inside the
 * sender's call. */
#include "unity.h"

#include <string.h>

#include "oc_core.h"
#include "oc_core_mem.h"

void setUp(void) {}
void tearDown(void) {}

#define UNIX0 1790000000u
#define L1    100u /* the OCSS link: core 1's handle */
#define L2    200u /* core 2's handle */
#define CELL  10u  /* cell 1's link on core 1 */
#define TA    0x0000aaaau
#define LEG   7u

typedef struct {
    oc_core_mem_t   mem;
    oc_core_store_t st;
    oc_core_route_t rt;
    oc_core_t       k;
    uint32_t        closed[8];
    int             nclosed;
} core_t;

static core_t   C1, C2;
static uint64_t NOW;
static int      CUT; /* frames between the cores are lost */

typedef struct {
    int           to; /* 1 or 2 */
    oc_core_msg_t m;
} frame_t;
static frame_t Q[256];
static int     QH, QT;
static oc_core_msg_t CELL_RX[256]; /* what core 1 sent cell 1 */
static int           NCELL;
static uint8_t       CLIP[2 * OC_CORE_PLAY_BYTES];
static uint8_t NA[OC_SIG_NUMBER_LEN], ECHO2[OC_SIG_NUMBER_LEN], PLAY2[OC_SIG_NUMBER_LEN], SUB2[OC_SIG_NUMBER_LEN];

static int send1(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    if (link == CELL) {
        CELL_RX[NCELL++ % 256] = *m;
    } else if (link == L1 && !CUT) {
        Q[QT++ % 256] = (frame_t){ 2, *m };
    }
    return 0;
}
static int send2(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    if (link == L2 && !CUT) Q[QT++ % 256] = (frame_t){ 1, *m };
    return 0;
}
static void close1(void *c, uint32_t link) { (void)c; C1.closed[C1.nclosed++ % 8] = link; }
static void close2(void *c, uint32_t link) { (void)c; C2.closed[C2.nclosed++ % 8] = link; }
static void rnd(void *c, uint8_t *out, size_t n)
{
    (void)c;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(i * 7u + 1u);
}
static uint32_t unix_now(void *c)
{
    (void)c;
    return UNIX0 + (uint32_t)(NOW / 1000000u);
}

static void pump(void)
{
    while (QH != QT) {
        frame_t f = Q[QH++ % 256];
        if (f.to == 1) oc_core_peer_rx(&C1.k, L1, &f.m, NOW);
        else oc_core_peer_rx(&C2.k, L2, &f.m, NOW);
    }
}

static void advance(uint64_t us)
{
    NOW += us;
    oc_core_tick(&C1.k, NOW);
    oc_core_tick(&C2.k, NOW);
    pump();
}

static void number(const char *t, uint8_t out[OC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(t, strlen(t), out));
}

static void make_core(core_t *c, uint16_t id, const oc_core_io_t *io, const char *echo, const char *play)
{
    uint8_t r[32];
    memset(r, 0x11 * id, 32);
    memset(c, 0, sizeof(*c));
    oc_core_mem_init(&c->mem);
    c->st = oc_core_mem_store(&c->mem);
    TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&c->st, id, 1800, r, UNIX0));
    oc_core_route_init(&c->rt, id);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&c->rt, "8831606", 1, 1));
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&c->rt, "8831503", 2, 2));
    oc_core_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = id;
    cfg.key_id = id;
    number(echo, cfg.echo_number);
    if (play != NULL) {
        number(play, cfg.playback_number);
        cfg.clip = CLIP;
        cfg.clip_len = sizeof(CLIP);
    }
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&c->k, io, &c->st, &c->rt, &cfg));
}

/* Two cores, the OCSS link up (core 1 dialled), and A registered on cell 1
 * of core 1. */
static void world(void)
{
    static const oc_core_io_t IO1 = { NULL, send1, close1, rnd, unix_now, NULL };
    static const oc_core_io_t IO2 = { NULL, send2, close2, rnd, unix_now, NULL };
    for (unsigned i = 0; i < sizeof(CLIP); i++) CLIP[i] = (uint8_t)(0xC0 + i / OC_CORE_PLAY_BYTES);
    NOW = 1000000u;
    QH = QT = NCELL = CUT = 0;
    make_core(&C1, 1, &IO1, "+883160655500100", "+883160655500101");
    make_core(&C2, 2, &IO2, "+883150355500100", "+883150355500101");
    number("+883160655501234", NA);
    number("+883150355500100", ECHO2);
    number("+883150355500101", PLAY2);
    number("+883150355501234", SUB2);
    /* cell 1 on core 1, A registered there */
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&C1.k, 1, "A", OC_SIG_MODE_PART15, 0));
    oc_core_msg_t h;
    memset(&h, 0, sizeof(h));
    h.type = OC_CORE_HELLO;
    h.u.hello.proto = OC_CORE_PROTO;
    h.u.hello.cell_id = 1;
    h.u.hello.boot_id = 1;
    oc_core_link_up(&C1.k, CELL, NOW);
    oc_core_rx(&C1.k, CELL, &h, NOW);
    uint8_t got[OC_SIG_NUMBER_LEN];
    oc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, oc_core_sub_add(&C1.k, NA, got));
    TEST_ASSERT_EQUAL_INT(0, C1.st.sub_get(C1.st.ctx, NA, &s));
    s.activated = 1;
    s.tmid = TA;
    TEST_ASSERT_EQUAL_INT(0, C1.st.sub_put(C1.st.ctx, &s));
    oc_core_loc_t l = { { 0 }, 1, TA, UNIX0 + 3600u, 0, { 0 } };
    memcpy(l.number, NA, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, C1.st.loc_put(C1.st.ctx, &l));
    /* the OCSS link: TLS showed each side the other's pinned certificate */
    oc_core_peer_up(&C2.k, L2, 1, 0, NOW);
    oc_core_peer_up(&C1.k, L1, 2, 1, NOW);
    pump();
}

/* What cell 1 got of type since index from, newest first. */
static const oc_core_msg_t *cell_got(int from, uint8_t type)
{
    for (int i = NCELL - 1; i >= from && i >= NCELL - 256; i--) {
        if (CELL_RX[i % 256].type == type) return &CELL_RX[i % 256];
    }
    return NULL;
}

static int cell_count(int from, uint8_t type)
{
    int n = 0;
    for (int i = from; i < NCELL; i++) n += CELL_RX[i % 256].type == type;
    return n;
}

static void cell_msg(uint8_t type, uint8_t cause)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = LEG;
    m.u.call.cause = cause;
    oc_core_rx(&C1.k, CELL, &m, NOW);
    pump();
}

static void cell_media(const char *s)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_MEDIA;
    m.u.media.ref = LEG;
    m.u.media.len = (uint8_t)strlen(s);
    memcpy(m.u.media.data, s, m.u.media.len);
    oc_core_rx(&C1.k, CELL, &m, NOW);
    pump();
}

static void dial(const uint8_t called[OC_SIG_NUMBER_LEN])
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = LEG;
    memcpy(m.u.call_route.caller, NA, OC_SIG_NUMBER_LEN);
    memcpy(m.u.call_route.called, called, OC_SIG_NUMBER_LEN);
    oc_core_rx(&C1.k, CELL, &m, NOW);
    pump();
}

static const oc_core_cdr_t *last_cdr(core_t *c)
{
    TEST_ASSERT_TRUE(c->mem.d.ncdr > 0);
    return &c->mem.d.cdr[(c->mem.d.ncdr - 1u) % OC_CORE_MEM_LOG];
}

static void test_hello_brings_the_link_up_both_ways(void)
{
    world();
    TEST_ASSERT_TRUE(oc_core_peer_linked(&C1.k, 2));
    TEST_ASSERT_TRUE(oc_core_peer_linked(&C2.k, 1));
    TEST_ASSERT_FALSE(oc_core_peer_linked(&C1.k, 3));
    for (int i = 0; i < 6; i++) advance(5000000u); /* 30 s: PING and PONG keep it up */
    TEST_ASSERT_TRUE(oc_core_peer_linked(&C1.k, 2));
    TEST_ASSERT_TRUE(oc_core_peer_linked(&C2.k, 1));
}

static void test_a_hello_from_another_core_is_refused_and_audited(void)
{
    world();
    oc_core_peer_up(&C2.k, L2 + 1u, 3, 0, NOW); /* core 2 was shown core 3's certificate */
    oc_core_msg_t h;
    memset(&h, 0, sizeof(h));
    h.type = OC_OCSS_HELLO;
    h.u.peer_hello.proto = OC_OCSS_PROTO;
    h.u.peer_hello.core_id = 1; /* but it claims to be core 1 */
    oc_core_peer_rx(&C2.k, L2 + 1u, &h, NOW);
    TEST_ASSERT_NOT_NULL(oc_core_mem_audit(&C2.mem, OC_CORE_AUDIT_PEER_REJECT));
    TEST_ASSERT_EQUAL_UINT32(L2 + 1u, C2.closed[C2.nclosed - 1]);
    TEST_ASSERT_TRUE(oc_core_peer_linked(&C2.k, 1)); /* the good link stays */
    oc_core_peer_up(&C2.k, L2 + 2u, 1, 0, NOW);
    h.u.peer_hello.proto = OC_OCSS_PROTO + 1u; /* a version it does not speak */
    oc_core_peer_rx(&C2.k, L2 + 2u, &h, NOW);
    TEST_ASSERT_EQUAL_UINT32(L2 + 2u, C2.closed[C2.nclosed - 1]);
}

static void test_a_link_with_no_hello_or_gone_silent_is_dropped(void)
{
    world();
    oc_core_peer_up(&C2.k, L2 + 1u, 3, 0, NOW); /* never says HELLO */
    advance(OC_CORE_SETUP_US);
    TEST_ASSERT_EQUAL_UINT32(L2 + 1u, C2.closed[C2.nclosed - 1]);
    CUT = 1; /* the WireGuard path goes */
    advance(OC_CORE_DEAD_US);
    TEST_ASSERT_FALSE(oc_core_peer_linked(&C1.k, 2));
    TEST_ASSERT_FALSE(oc_core_peer_linked(&C2.k, 1));
    TEST_ASSERT_EQUAL_UINT32(L1, C1.closed[C1.nclosed - 1]);
}

static void test_core_2s_echo_service_from_a_cell_on_core_1(void)
{
    world();
    int from = NCELL;
    dial(ECHO2);
    TEST_ASSERT_EQUAL_UINT32(LEG, cell_got(from, OC_CORE_CALL_ALERT)->u.call.ref); /* core 2 rings at once */
    advance(OC_CORE_ECHO_US);
    TEST_ASSERT_EQUAL_UINT32(LEG, cell_got(from, OC_CORE_CALL_ANSWER)->u.call.ref);
    cell_media("HELLO");
    const oc_core_msg_t *d = cell_got(from, OC_CORE_MEDIA);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
    TEST_ASSERT_EQUAL_MEMORY("HELLO", d->u.media.data, 5);
    cell_msg(OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NORMAL);
    const oc_core_cdr_t *c1 = last_cdr(&C1), *c2 = last_cdr(&C2);
    TEST_ASSERT_EQUAL_UINT32(1, c1->cell_a); /* core 1: its cell's leg; the other is core 2's */
    TEST_ASSERT_EQUAL_UINT32(0, c1->cell_b);
    TEST_ASSERT_EQUAL_UINT32(0, c2->cell_a); /* core 2: a peer's leg and its own service */
    TEST_ASSERT_EQUAL_UINT32(0, c2->cell_b);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ECHO2, c2->called, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NA, c2->caller, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_NOT_EQUAL(0, c1->answer);
    TEST_ASSERT_NOT_EQUAL(0, c2->answer);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NORMAL, c2->cause);
}

static void test_core_2s_playback_reaches_the_cell_one_payload_per_frame(void)
{
    world();
    int from = NCELL;
    dial(PLAY2);
    advance(OC_CORE_ECHO_US);
    TEST_ASSERT_NOT_NULL(cell_got(from, OC_CORE_CALL_ANSWER));
    advance(OC_CORE_PLAY_LEAD_US);
    for (unsigned i = 0; i < 6; i++) {
        const oc_core_msg_t *d = cell_got(NCELL - 1, OC_CORE_MEDIA);
        TEST_ASSERT_NOT_NULL(d);
        TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
        TEST_ASSERT_EQUAL_UINT16(i, d->u.media.seq);
        TEST_ASSERT_EQUAL_UINT8(OC_CORE_PLAY_BYTES, d->u.media.len);
        TEST_ASSERT_EQUAL_MEMORY(CLIP + (i % 2u) * OC_CORE_PLAY_BYTES, d->u.media.data, OC_CORE_PLAY_BYTES);
        int before = NCELL;
        advance(OC_CORE_PLAY_US);
        TEST_ASSERT_EQUAL_INT(1, cell_count(before, OC_CORE_MEDIA));
    }
}

static void test_a_number_core_2_does_not_have_is_unreachable(void)
{
    world();
    int from = NCELL;
    dial(SUB2);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_UNREACHABLE, cell_got(from, OC_CORE_CALL_RELEASE)->u.call.cause);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_UNREACHABLE, last_cdr(&C1)->cause);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_UNREACHABLE, last_cdr(&C2)->cause);
}

static void test_core_2_unreachable_is_a_network_failure_at_once(void)
{
    world();
    oc_core_peer_down(&C1.k, L1, NOW);
    int from = NCELL;
    dial(ECHO2);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NET_FAILURE, cell_got(from, OC_CORE_CALL_RELEASE)->u.call.cause);
    TEST_ASSERT_EQUAL_UINT32(0, C2.mem.d.ncdr); /* core 2 never heard of it */
}

static void test_core_2_silent_after_setup_times_out_in_10_s(void)
{
    world();
    CUT = 1; /* the setup is lost, and nothing comes back */
    int from = NCELL;
    dial(ECHO2);
    TEST_ASSERT_NULL(cell_got(from, OC_CORE_CALL_RELEASE));
    advance(OC_CORE_SETUP_US);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NET_FAILURE, cell_got(from, OC_CORE_CALL_RELEASE)->u.call.cause);
}

static void test_a_lost_link_ends_its_calls_on_both_cores(void)
{
    world();
    int from = NCELL;
    dial(ECHO2);
    advance(OC_CORE_ECHO_US);
    oc_core_peer_down(&C1.k, L1, NOW);
    oc_core_peer_down(&C2.k, L2, NOW);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NET_FAILURE, cell_got(from, OC_CORE_CALL_RELEASE)->u.call.cause);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NET_FAILURE, last_cdr(&C1)->cause);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NET_FAILURE, last_cdr(&C2)->cause);
}

/* What core 2 answers core 1 for one setup. */
static uint8_t setup_cause(uint32_t ref, const uint8_t called[OC_SIG_NUMBER_LEN], uint8_t hop)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_CALL_SETUP;
    m.u.setup.call_ref = ref;
    memcpy(m.u.setup.caller, NA, OC_SIG_NUMBER_LEN);
    memcpy(m.u.setup.called, called, OC_SIG_NUMBER_LEN);
    m.u.setup.hop = hop;
    int at = QT;
    oc_core_peer_rx(&C2.k, L2, &m, NOW);
    for (int i = at; i < QT; i++) {
        const oc_core_msg_t *r = &Q[i % 256].m;
        if (r->u.call.ref == ref && r->type == OC_OCSS_CALL_RELEASE) return r->u.call.cause;
        if (r->u.call.ref == ref && r->type == OC_OCSS_CALL_ALERT) return 0xAA;
    }
    return 0xFF;
}

static void test_core_2_never_sends_a_call_on_and_limits_a_peer(void)
{
    world();
    QH = QT; /* these setups are inspected, not delivered */
    TEST_ASSERT_EQUAL_HEX8(OC_SIG_CAUSE_UNREACHABLE, setup_cause(OC_CORE_REF_CORE | 50u, NA, 0)); /* core 1's block */
    TEST_ASSERT_EQUAL_HEX8(OC_SIG_CAUSE_NET_FAILURE, setup_cause(OC_CORE_REF_CORE | 51u, ECHO2, OC_CORE_HOP_MAX + 1u));
    for (uint32_t i = 0; i < OC_CORE_PEER_CALLS; i++) {
        TEST_ASSERT_EQUAL_HEX8(0xAA, setup_cause(OC_CORE_REF_CORE | (60u + i), ECHO2, 0)); /* ringing */
    }
    TEST_ASSERT_EQUAL_HEX8(OC_SIG_CAUSE_NET_FAILURE, setup_cause(OC_CORE_REF_CORE | 70u, ECHO2, 0));
    TEST_ASSERT_EQUAL_HEX8(0xFF, setup_cause(OC_CORE_REF_CORE | 60u, ECHO2, 0)); /* a repeat: ignored */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hello_brings_the_link_up_both_ways);
    RUN_TEST(test_a_hello_from_another_core_is_refused_and_audited);
    RUN_TEST(test_a_link_with_no_hello_or_gone_silent_is_dropped);
    RUN_TEST(test_core_2s_echo_service_from_a_cell_on_core_1);
    RUN_TEST(test_core_2s_playback_reaches_the_cell_one_payload_per_frame);
    RUN_TEST(test_a_number_core_2_does_not_have_is_unreachable);
    RUN_TEST(test_core_2_unreachable_is_a_network_failure_at_once);
    RUN_TEST(test_core_2_silent_after_setup_times_out_in_10_s);
    RUN_TEST(test_a_lost_link_ends_its_calls_on_both_cores);
    RUN_TEST(test_core_2_never_sends_a_call_on_and_limits_a_peer);
    return UNITY_END();
}
