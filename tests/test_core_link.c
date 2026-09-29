/* The core's links (network-core spec §6, §7.9): HELLO and its refusals,
 * one link per cell, a new boot purging the cell's state, liveness, revoking
 * a cell. */
#include "unity.h"

#include "core_fixture.h"

void setUp(void) {}
void tearDown(void) {}

static void test_hello_is_acked_with_the_cell_settings(void)
{
    core_world();
    hello(10, 2, 0xB007);
    const lc_core_msg_t *a = sent(10, LC_CORE_HELLO_ACK);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_MODE_PART97, a->u.hello_ack.mode); /* per cell */
    TEST_ASSERT_EQUAL_UINT16(1800, a->u.hello_ack.period_s);
    TEST_ASSERT_EQUAL_UINT16(1, a->u.hello_ack.key_id);
    uint8_t echo[LC_SIG_NUMBER_LEN];
    number(ECHO_NUM, echo);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(echo, a->u.hello_ack.echo_number, LC_SIG_NUMBER_LEN);
    lc_core_cell_t c;
    TEST_ASSERT_EQUAL_INT(0, ST.cell_get(ST.ctx, 2, &c));
    TEST_ASSERT_EQUAL_UINT64(0xB007, c.boot_id);
    TEST_ASSERT_EQUAL_INT(0, NCLOSED);
}

static void test_hello_refusals_close_the_link_and_are_audited(void)
{
    core_world();
    hello(10, 9, 1); /* unknown cell */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_NAK_UNKNOWN_CELL, sent(10, LC_CORE_HELLO_NAK)->u.hello_nak.reason);
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
    const lc_core_audit_t *a = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_CELL_REJECT);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(9, a->cell_id);

    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_revoke(&K, 2, NOW));
    hello(11, 2, 1); /* disabled */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_NAK_DISABLED, sent(11, LC_CORE_HELLO_NAK)->u.hello_nak.reason);

    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO;
    m.u.hello.proto = LC_CORE_PROTO - 1u; /* proto 1: AV_RES with XRES (network-core spec §19.1), not spoken */
    m.u.hello.cell_id = 1;
    lc_core_link_up(&K, 12, NOW);
    rx(12, &m);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_NAK_VERSION, sent(12, LC_CORE_HELLO_NAK)->u.hello_nak.reason);
    TEST_ASSERT_EQUAL_INT(3, NCLOSED);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_cell_add(&K, 1, "again", LC_SIG_MODE_PART15, 0)); /* exists */
}

static void test_nothing_but_hello_before_hello(void)
{
    core_world();
    lc_core_link_up(&K, 10, NOW);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.tmid = 1;
    m.u.av_req.count = 1;
    rx(10, &m);
    TEST_ASSERT_EQUAL_INT(0, NSENT);
    m.type = LC_CORE_PING; /* liveness works on any link */
    rx(10, &m);
    TEST_ASSERT_NOT_NULL(sent(10, LC_CORE_PONG));
}

static void put_location(uint32_t cell, const char *num)
{
    lc_core_loc_t l;
    memset(&l, 0, sizeof(l));
    number(num, l.number);
    l.cell_id = cell;
    l.tmid = 0x1234;
    l.expires = UNIX0 + 3600u;
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

/* §7.9: a HELLO with a new boot id purges the cell's locations and unused
 * vectors; the same boot id (the link dropped, the process didn't) keeps
 * them. A second link for a cell replaces the first. */
static void test_new_boot_purges_same_boot_keeps(void)
{
    core_world();
    hello(10, 1, 111);
    put_location(1, "+883160655501234");
    put_location(2, "+883160655501235");
    lc_core_av_issued_t av;
    memset(&av, 0, sizeof(av));
    number("+883160655501234", av.number);
    av.cell_id = 1;
    TEST_ASSERT_EQUAL_INT(0, ST.av_put(ST.ctx, &av));
    lc_core_link_down(&K, 10, NOW);
    hello(11, 1, 111); /* the same process, reconnected */
    lc_core_loc_t l;
    uint8_t n1[LC_SIG_NUMBER_LEN], n2[LC_SIG_NUMBER_LEN];
    number("+883160655501234", n1);
    number("+883160655501235", n2);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, n1, &l));
    hello(12, 1, 222); /* restarted, and on a new link while the old one lingers */
    TEST_ASSERT_EQUAL_UINT32(11, CLOSED[NCLOSED - 1]); /* the old link was dropped */
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n1, &l));
    TEST_ASSERT_EQUAL_INT(-1, ST.av_get(ST.ctx, n1, av.rand, &av));
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, n2, &l)); /* another cell's: untouched */
}

static void test_ping_when_idle_and_down_when_silent(void)
{
    core_world();
    hello(10, 1, 1);
    int from = NSENT;
    advance(LC_CORE_PING_US);
    TEST_ASSERT_NOT_NULL(sent_since(from, 10, LC_CORE_PING));
    lc_core_msg_t pong;
    memset(&pong, 0, sizeof(pong));
    pong.type = LC_CORE_PONG;
    rx(10, &pong);
    advance(LC_CORE_DEAD_US - 1u);
    TEST_ASSERT_EQUAL_INT(0, NCLOSED); /* it answered: alive */
    advance(1u);
    TEST_ASSERT_EQUAL_INT(1, NCLOSED);
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
}

static void test_revoked_cell_loses_its_link(void)
{
    core_world();
    hello(10, 1, 1);
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_revoke(&K, 1, NOW));
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_cell_revoke(&K, 7, NOW));
}

static void test_core_needs_its_network_key(void)
{
    static lc_core_mem_t mem;
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_route_t rt;
    lc_core_route_init(&rt, 1);
    lc_core_cfg_t cfg = core_cfg();
    static lc_core_t k;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_init(&k, &CORE_IO, &st, &rt, &cfg));
}

/* Channel-list spec §8: a group's list goes to its cells in CELL_CFG, after
 * HELLO_ACK and whenever it changes; the core numbers the versions and keeps
 * the list across a restart. */
static void test_channel_list_goes_to_the_group(void)
{
    core_world();
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&K, 3, "C", LC_SIG_MODE_PART15, 5));
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&K, 4, "D", LC_SIG_MODE_PART15, 5));
    lc_sig_chan_list_t l;
    memset(&l, 0, sizeof(l));
    l.ver = 77; /* the core numbers versions itself */
    l.count = 1;
    l.freq_hz[0] = 917250000u;
    hello(10, 1, 1); /* group 0: none */
    hello(30, 3, 1); /* group 5, before it has a list */
    TEST_ASSERT_NULL(sent(30, LC_CORE_CELL_CFG));
    TEST_ASSERT_EQUAL_INT(1, lc_core_chan_list_set(&K, 5, &l, NOW));
    const lc_core_msg_t *c = sent(30, LC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.count);
    TEST_ASSERT_EQUAL_UINT32(917250000u, c->u.cell_cfg.list.freq_hz[0]);
    TEST_ASSERT_NULL(sent(10, LC_CORE_CELL_CFG));

    int from = NSENT;
    hello(40, 4, 1); /* a cell of the group comes up: HELLO_ACK, then the list */
    TEST_ASSERT_NOT_NULL(sent_since(from, 40, LC_CORE_HELLO_ACK));
    c = sent_since(from, 40, LC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_INT(2, lc_core_chan_list_set(&K, 5, &l, NOW)); /* a change reaches both */
    TEST_ASSERT_EQUAL_UINT8(2, sent(30, LC_CORE_CELL_CFG)->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_UINT8(2, sent(40, LC_CORE_CELL_CFG)->u.cell_cfg.list.ver);

    core_restart(); /* the list is in the store */
    from = NSENT;
    hello(31, 3, 1);
    c = sent_since(from, 31, LC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(2, c->u.cell_cfg.list.ver);

    l.count = LC_SIG_CHAN_MAX + 1u;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_chan_list_set(&K, 5, &l, NOW));
    l.count = 1;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_chan_list_set(&K, 0, &l, NOW)); /* 0: no group */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_channel_list_goes_to_the_group);
    RUN_TEST(test_hello_is_acked_with_the_cell_settings);
    RUN_TEST(test_hello_refusals_close_the_link_and_are_audited);
    RUN_TEST(test_nothing_but_hello_before_hello);
    RUN_TEST(test_new_boot_purges_same_boot_keeps);
    RUN_TEST(test_ping_when_idle_and_down_when_silent);
    RUN_TEST(test_revoked_cell_loses_its_link);
    RUN_TEST(test_core_needs_its_network_key);
    return UNITY_END();
}
