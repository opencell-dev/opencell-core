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
    const oc_core_msg_t *a = sent(10, OC_CORE_HELLO_ACK);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_MODE_PART97, a->u.hello_ack.mode); /* per cell */
    TEST_ASSERT_EQUAL_UINT16(1800, a->u.hello_ack.period_s);
    TEST_ASSERT_EQUAL_UINT16(1, a->u.hello_ack.key_id);
    uint8_t echo[OC_SIG_NUMBER_LEN];
    number(ECHO_NUM, echo);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(echo, a->u.hello_ack.echo_number, OC_SIG_NUMBER_LEN);
    oc_core_cell_t c;
    TEST_ASSERT_EQUAL_INT(0, ST.cell_get(ST.ctx, 2, &c));
    TEST_ASSERT_EQUAL_UINT64(0xB007, c.boot_id);
    TEST_ASSERT_EQUAL_INT(0, NCLOSED);
}

static void test_hello_refusals_close_the_link_and_are_audited(void)
{
    core_world();
    hello(10, 9, 1); /* unknown cell */
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_NAK_UNKNOWN_CELL, sent(10, OC_CORE_HELLO_NAK)->u.hello_nak.reason);
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
    const oc_core_audit_t *a = oc_core_mem_audit(&MEM, OC_CORE_AUDIT_CELL_REJECT);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(9, a->cell_id);

    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_revoke(&K, 2, NOW));
    hello(11, 2, 1); /* disabled */
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_NAK_DISABLED, sent(11, OC_CORE_HELLO_NAK)->u.hello_nak.reason);

    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_HELLO;
    m.u.hello.proto = OC_CORE_PROTO - 1u; /* proto 1: AV_RES with XRES (network-core spec §19.1), not spoken */
    m.u.hello.cell_id = 1;
    oc_core_link_up(&K, 12, NOW);
    rx(12, &m);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_NAK_VERSION, sent(12, OC_CORE_HELLO_NAK)->u.hello_nak.reason);
    TEST_ASSERT_EQUAL_INT(3, NCLOSED);
    TEST_ASSERT_EQUAL_INT(-1, oc_core_cell_add(&K, 1, "again", OC_SIG_MODE_PART15, 0)); /* exists */
}

static void test_nothing_but_hello_before_hello(void)
{
    core_world();
    oc_core_link_up(&K, 10, NOW);
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_AV_REQ;
    m.u.av_req.tmid = 1;
    m.u.av_req.count = 1;
    rx(10, &m);
    TEST_ASSERT_EQUAL_INT(0, NSENT);
    m.type = OC_CORE_PING; /* liveness works on any link */
    rx(10, &m);
    TEST_ASSERT_NOT_NULL(sent(10, OC_CORE_PONG));
}

static void put_location(uint32_t cell, const char *num)
{
    oc_core_loc_t l;
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
    oc_core_av_issued_t av;
    memset(&av, 0, sizeof(av));
    number("+883160655501234", av.number);
    av.cell_id = 1;
    TEST_ASSERT_EQUAL_INT(0, ST.av_put(ST.ctx, &av));
    oc_core_link_down(&K, 10, NOW);
    hello(11, 1, 111); /* the same process, reconnected */
    oc_core_loc_t l;
    uint8_t n1[OC_SIG_NUMBER_LEN], n2[OC_SIG_NUMBER_LEN];
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
    advance(OC_CORE_PING_US);
    TEST_ASSERT_NOT_NULL(sent_since(from, 10, OC_CORE_PING));
    oc_core_msg_t pong;
    memset(&pong, 0, sizeof(pong));
    pong.type = OC_CORE_PONG;
    rx(10, &pong);
    advance(OC_CORE_DEAD_US - 1u);
    TEST_ASSERT_EQUAL_INT(0, NCLOSED); /* it answered: alive */
    advance(1u);
    TEST_ASSERT_EQUAL_INT(1, NCLOSED);
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
}

static void test_revoked_cell_loses_its_link(void)
{
    core_world();
    hello(10, 1, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_revoke(&K, 1, NOW));
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
    TEST_ASSERT_EQUAL_INT(-1, oc_core_cell_revoke(&K, 7, NOW));
}

static void test_core_needs_its_network_key(void)
{
    static oc_core_mem_t mem;
    oc_core_mem_init(&mem);
    oc_core_store_t st = oc_core_mem_store(&mem);
    oc_core_route_t rt;
    oc_core_route_init(&rt, 1);
    oc_core_cfg_t cfg = core_cfg();
    static oc_core_t k;
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&k, &CORE_IO, &st, &rt, &cfg));
    uint8_t r[32];
    memset(r, 0x11, 32);
    TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&st, 1, 1800, r, UNIX0));
    mem.fail_reads = OC_CORE_MEM_FAIL_NETKEY_GET; /* a key that can't be read: -1 too, as documented */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&k, &CORE_IO, &st, &rt, &cfg));
    mem.fail_reads = 0;
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&k, &CORE_IO, &st, &rt, &cfg));
}

/* Channel-list spec §8: a group's list goes to its cells in CELL_CFG, after
 * HELLO_ACK and whenever it changes; the core numbers the versions and keeps
 * the list across a restart. */
static void test_channel_list_goes_to_the_group(void)
{
    core_world();
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&K, 3, "C", OC_SIG_MODE_PART15, 5));
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&K, 4, "D", OC_SIG_MODE_PART15, 5));
    oc_sig_chan_list_t l;
    memset(&l, 0, sizeof(l));
    l.ver = 77; /* the core numbers versions itself */
    l.count = 1;
    l.freq_hz[0] = 917250000u;
    hello(10, 1, 1); /* group 0: none */
    hello(30, 3, 1); /* group 5, before it has a list */
    TEST_ASSERT_NULL(sent(30, OC_CORE_CELL_CFG));
    TEST_ASSERT_EQUAL_INT(1, oc_core_chan_list_set(&K, 5, &l, NOW));
    const oc_core_msg_t *c = sent(30, OC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.count);
    TEST_ASSERT_EQUAL_UINT32(917250000u, c->u.cell_cfg.list.freq_hz[0]);
    TEST_ASSERT_NULL(sent(10, OC_CORE_CELL_CFG));

    int from = NSENT;
    hello(40, 4, 1); /* a cell of the group comes up: HELLO_ACK, then the list */
    TEST_ASSERT_NOT_NULL(sent_since(from, 40, OC_CORE_HELLO_ACK));
    c = sent_since(from, 40, OC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_INT(2, oc_core_chan_list_set(&K, 5, &l, NOW)); /* a change reaches both */
    TEST_ASSERT_EQUAL_UINT8(2, sent(30, OC_CORE_CELL_CFG)->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_UINT8(2, sent(40, OC_CORE_CELL_CFG)->u.cell_cfg.list.ver);

    core_restart(); /* the list is in the store */
    from = NSENT;
    hello(31, 3, 1);
    c = sent_since(from, 31, OC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(2, c->u.cell_cfg.list.ver);

    l.count = OC_SIG_CHAN_MAX + 1u;
    TEST_ASSERT_EQUAL_INT(-1, oc_core_chan_list_set(&K, 5, &l, NOW));
    l.count = 1;
    TEST_ASSERT_EQUAL_INT(-1, oc_core_chan_list_set(&K, 0, &l, NOW)); /* 0: no group */
}

/* A cell or network-key read that fails is not "unknown cell" or "core
 * disabled": the HELLO is refused by closing the link, with no HELLO_NAK
 * and no CELL_REJECT audit to mislead; the cell reconnects. */
static void test_a_failed_read_refuses_hello_without_a_nak(void)
{
    static const unsigned fails[] = { OC_CORE_MEM_FAIL_CELL_GET, OC_CORE_MEM_FAIL_NETKEY_GET };
    for (unsigned i = 0; i < 2; i++) {
        core_world();
        MEM.fail_reads = fails[i];
        hello(10, 1, 1);
        MEM.fail_reads = 0;
        TEST_ASSERT_NULL(sent(10, OC_CORE_HELLO_NAK));
        TEST_ASSERT_NULL(sent(10, OC_CORE_HELLO_ACK));
        TEST_ASSERT_EQUAL_INT(1, NCLOSED);
        TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
        TEST_ASSERT_NULL(oc_core_mem_audit(&MEM, OC_CORE_AUDIT_CELL_REJECT));
        hello(11, 1, 1);
        TEST_ASSERT_NOT_NULL(sent(11, OC_CORE_HELLO_ACK));
    }
}

/* A cell whose record could not be read is not added again over it. */
static void test_a_failed_cell_read_adds_nothing(void)
{
    core_world();
    MEM.fail_reads = OC_CORE_MEM_FAIL_CELL_GET;
    TEST_ASSERT_EQUAL_INT(-2, oc_core_cell_add(&K, 1, "again", OC_SIG_MODE_PART97, 3)); /* not "exists" */
    MEM.fail_reads = 0;
    oc_core_cell_t c;
    TEST_ASSERT_EQUAL_INT(0, ST.cell_get(ST.ctx, 1, &c));
    TEST_ASSERT_EQUAL_STRING("A", c.name);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_MODE_PART15, c.mode);
    TEST_ASSERT_EQUAL_UINT16(0, c.list_id);
}

/* A channel list whose current version could not be read is not replaced
 * by a "version 1" that would go backwards. */
static void test_a_failed_list_read_changes_no_list(void)
{
    core_world();
    oc_sig_chan_list_t l, got;
    memset(&l, 0, sizeof(l));
    l.count = 1;
    l.freq_hz[0] = 917250000u;
    TEST_ASSERT_EQUAL_INT(1, oc_core_chan_list_set(&K, 5, &l, NOW));
    TEST_ASSERT_EQUAL_INT(2, oc_core_chan_list_set(&K, 5, &l, NOW));
    l.freq_hz[0] = 918000000u;
    MEM.fail_reads = OC_CORE_MEM_FAIL_LIST_GET;
    TEST_ASSERT_EQUAL_INT(-1, oc_core_chan_list_set(&K, 5, &l, NOW));
    MEM.fail_reads = 0;
    TEST_ASSERT_EQUAL_INT(0, ST.list_get(ST.ctx, 5, &got));
    TEST_ASSERT_EQUAL_UINT8(2, got.ver);
    TEST_ASSERT_EQUAL_UINT32(917250000u, got.freq_hz[0]);
    TEST_ASSERT_EQUAL_INT(3, oc_core_chan_list_set(&K, 5, &l, NOW));
}

/* CELL_CFG that can't be sent (network-core spec §7.10: the cell serves on
 * its old list meanwhile) never costs a cell its link: the link is marked
 * pending and the core retries from its tick, 1 s doubling to 60 s,
 * logging only when the state changes. */
#define US_(s) ((uint64_t)(s) * 1000000ull)
static int list_reads, list_pass = -1; /* list_pass: reads that pass before the rest fail; -1 all pass */
static int (*mem_list_get)(void *ctx, uint16_t list_id, oc_sig_chan_list_t *out);
static int list_get_counting(void *ctx, uint16_t list_id, oc_sig_chan_list_t *out)
{
    if (list_pass >= 0 && list_reads++ >= list_pass) return OC_CORE_STORE_FAILED;
    return mem_list_get(ctx, list_id, out);
}
static int nlog;
static void count_log(void *ctx, const char *line)
{
    (void)ctx;
    if (strstr(line, "CELL_CFG") != NULL) nlog++;
}
static void ping_from(uint32_t link)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_PING;
    rx(link, &m);
}
static oc_core_link_t *link_no(uint32_t link)
{
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (K.links[i].used && K.links[i].link == link) return &K.links[i];
    }
    return NULL;
}

static void group5_world(void)
{
    core_world();
    K.io.log = count_log;
    nlog = 0;
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&K, 3, "C", OC_SIG_MODE_PART15, 5));
    oc_sig_chan_list_t l;
    memset(&l, 0, sizeof(l));
    l.count = 1;
    l.freq_hz[0] = 917250000u;
    TEST_ASSERT_EQUAL_INT(1, oc_core_chan_list_set(&K, 5, &l, NOW));
    mem_list_get = K.st.list_get;
    K.st.list_get = list_get_counting;
    list_reads = 0;
    list_pass = -1;
}

static void test_a_list_that_cant_be_read_at_hello_is_retried_not_dropped(void)
{
    group5_world();
    list_pass = 0; /* every list read fails */
    hello(30, 3, 1);
    TEST_ASSERT_NOT_NULL(sent(30, OC_CORE_HELLO_ACK)); /* the cell serves on */
    TEST_ASSERT_NULL(sent(30, OC_CORE_CELL_CFG));
    TEST_ASSERT_EQUAL_INT(0, NCLOSED);
    TEST_ASSERT_TRUE(link_no(30)->cfg_pending);
    TEST_ASSERT_EQUAL_INT(1, nlog);

    /* retries at +1 s, then +2, +4 s: each failing, none logged */
    static const uint64_t gaps_s[] = { 1, 2, 4 };
    for (unsigned i = 0; i < 3; i++) {
        int before = list_reads;
        ping_from(30);
        advance(US_(gaps_s[i]) - 1u);
        TEST_ASSERT_EQUAL_INT(before, list_reads); /* not yet */
        advance(1u);
        TEST_ASSERT_EQUAL_INT(before + 1, list_reads);
    }
    TEST_ASSERT_EQUAL_INT(1, nlog);
    TEST_ASSERT_EQUAL_INT(0, NCLOSED);

    list_pass = -1; /* the store answers again: the next retry (+8 s) sends it */
    ping_from(30);
    advance(US_(8));
    const oc_core_msg_t *c = sent(30, OC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.ver);
    TEST_ASSERT_FALSE(link_no(30)->cfg_pending);
    TEST_ASSERT_EQUAL_INT(2, nlog); /* pending, then sent */
    list_pass = 0;
    list_reads = 0;
    ping_from(30);
    advance(US_(10));
    TEST_ASSERT_EQUAL_INT(0, list_reads); /* nothing more to do */
    list_pass = -1;
    K.st.list_get = mem_list_get;
}

/* The fan-out sends the list just written (no read back); a linked cell
 * whose own record can't be read keeps its link and is marked pending, and
 * gets the list at the retry. */
static void test_the_fan_out_retries_a_cell_it_cant_read(void)
{
    group5_world();
    hello(30, 3, 1);
    TEST_ASSERT_NOT_NULL(sent(30, OC_CORE_CELL_CFG));
    oc_sig_chan_list_t l;
    memset(&l, 0, sizeof(l));
    l.count = 1;
    l.freq_hz[0] = 918000000u;
    list_reads = 0;
    list_pass = 1; /* the version read passes; a read-back would fail */
    int from = NSENT;
    TEST_ASSERT_EQUAL_INT(2, oc_core_chan_list_set(&K, 5, &l, NOW));
    list_pass = -1;
    const oc_core_msg_t *c = sent_since(from, 30, OC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(2, c->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_UINT32(918000000u, c->u.cell_cfg.list.freq_hz[0]);
    TEST_ASSERT_FALSE(link_no(30)->cfg_pending);

    from = NSENT;
    MEM.fail_reads = OC_CORE_MEM_FAIL_CELL_GET;
    TEST_ASSERT_EQUAL_INT(3, oc_core_chan_list_set(&K, 5, &l, NOW)); /* stored; the push to cell 3 is pending */
    MEM.fail_reads = 0;
    TEST_ASSERT_NULL(sent_since(from, 30, OC_CORE_CELL_CFG));
    TEST_ASSERT_EQUAL_INT(0, NCLOSED);
    TEST_ASSERT_TRUE(link_no(30)->cfg_pending);
    ping_from(30);
    advance(US_(1));
    c = sent_since(from, 30, OC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(3, c->u.cell_cfg.list.ver);
    TEST_ASSERT_FALSE(link_no(30)->cfg_pending);
    K.st.list_get = mem_list_get;
}

/* Operator repair: a list whose stored row can't be read is replaced with
 * oc_core_chan_list_replace, at a version past the last one written (kept
 * apart from the row), so every cell takes it as a change; and pushed. */
static void test_an_unreadable_list_can_be_replaced(void)
{
    group5_world();
    K.st.list_get = mem_list_get;
    oc_sig_chan_list_t l, got;
    memset(&l, 0, sizeof(l));
    l.count = 1;
    l.freq_hz[0] = 918000000u;
    TEST_ASSERT_EQUAL_INT(2, oc_core_chan_list_set(&K, 5, &l, NOW));
    hello(30, 3, 1);
    int from = NSENT;
    MEM.fail_reads = OC_CORE_MEM_FAIL_LIST_GET; /* the row: unreadable */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_chan_list_set(&K, 5, &l, NOW));
    TEST_ASSERT_EQUAL_INT(3, oc_core_chan_list_replace(&K, 5, &l, NOW));
    MEM.fail_reads = 0;
    TEST_ASSERT_EQUAL_INT(0, ST.list_get(ST.ctx, 5, &got));
    TEST_ASSERT_EQUAL_UINT8(3, got.ver);
    const oc_core_msg_t *c = sent_since(from, 30, OC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(3, c->u.cell_cfg.list.ver);

    MEM.fail_reads = OC_CORE_MEM_FAIL_LIST_GET | OC_CORE_MEM_FAIL_LIST_VER_GET; /* nor the last version: refused */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_chan_list_replace(&K, 5, &l, NOW));
    MEM.fail_reads = 0;
    TEST_ASSERT_EQUAL_INT(0, ST.list_get(ST.ctx, 5, &got));
    TEST_ASSERT_EQUAL_UINT8(3, got.ver);
    TEST_ASSERT_EQUAL_INT(4, oc_core_chan_list_replace(&K, 5, &l, NOW)); /* readable: like set */
}

/* A CELL_STATUS part with `nt` terminals numbered from tmid0. */
static oc_core_msg_t status_part(uint8_t part, uint8_t nradio, uint8_t nt, uint32_t tmid0)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CELL_STATUS;
    m.u.cell_status.ver = OC_CORE_STATUS_VER;
    m.u.cell_status.part = part;
    m.u.cell_status.nradio = nradio;
    for (uint8_t i = 0; i < nradio; i++) {
        m.u.cell_status.radio[i].radio = i;
        m.u.cell_status.radio[i].pps = 1;
        m.u.cell_status.radio[i].late_slots = (uint16_t)(10u + i);
    }
    m.u.cell_status.nterm = nt;
    for (uint8_t i = 0; i < nt; i++) {
        m.u.cell_status.term[i].tmid = tmid0 + i;
        m.u.cell_status.term[i].rssi_dbm = -90;
    }
    return m;
}

/* NOC design §7.3: the latest whole report per linked cell, in memory. */
static void test_cell_status_is_kept_whole_per_link(void)
{
    core_world();
    oc_core_msg_t m = status_part(OC_CORE_STATUS_LAST, 1, 0, 0);
    oc_core_link_up(&K, 10, NOW);
    rx(10, &m); /* before HELLO: ignored */
    hello(10, 2, 1);
    TEST_ASSERT_NULL(oc_core_cell_tel(&K, 2));
    TEST_ASSERT_NULL(oc_core_cell_tel(&K, 1)); /* not linked */

    m = status_part(0, 1, 28, 0x100);
    rx(10, &m);
    TEST_ASSERT_NULL(oc_core_cell_tel(&K, 2)); /* not the last part yet */
    m = status_part(OC_CORE_STATUS_LAST | 1, 0, 3, 0x200);
    advance(5000000u);
    rx(10, &m);
    const oc_core_tel_t *t = oc_core_cell_tel(&K, 2);
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL_UINT8(1, t->nradio);
    TEST_ASSERT_EQUAL_UINT16(10, t->radio[0].late_slots);
    TEST_ASSERT_EQUAL_UINT8(31, t->nterm);
    TEST_ASSERT_EQUAL_HEX32(0x202, t->term[30].tmid);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 6u, t->at);

    /* a part out of order: the report being gathered is dropped, the published one stays */
    m = status_part(0, 1, 2, 0x300);
    rx(10, &m);
    m = status_part(OC_CORE_STATUS_LAST | 2, 0, 1, 0x400);
    rx(10, &m);
    TEST_ASSERT_EQUAL_UINT8(31, oc_core_cell_tel(&K, 2)->nterm);
    m = status_part(OC_CORE_STATUS_LAST | 1, 0, 1, 0x500); /* still waiting for a part 0 */
    rx(10, &m);
    TEST_ASSERT_EQUAL_UINT8(31, oc_core_cell_tel(&K, 2)->nterm);

    /* more than the core's room: the rest is left out */
    for (uint8_t p = 0; p < 3; p++) {
        m = status_part((uint8_t)(p | (p == 2 ? OC_CORE_STATUS_LAST : 0)), 2, 28, 0x1000u + p * 28u);
        rx(10, &m);
    }
    t = oc_core_cell_tel(&K, 2);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_TEL_RADIOS, t->nradio);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_TEL_TERMS, t->nterm);

    /* gone with the link */
    oc_core_link_down(&K, 10, NOW);
    TEST_ASSERT_NULL(oc_core_cell_tel(&K, 2));
    hello(11, 2, 1);
    TEST_ASSERT_NULL(oc_core_cell_tel(&K, 2));
}

/* The mode switch (NOC design §7.1 cell.mode): stored, the link dropped,
 * the new mode in the next HELLO_ACK. */
static void test_a_mode_change_drops_the_link_and_the_next_hello_takes_it(void)
{
    core_world();
    hello(10, 1, 1);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_MODE_PART15, sent(10, OC_CORE_HELLO_ACK)->u.hello_ack.mode);
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_mode(&K, 1, OC_SIG_MODE_PART97, NOW));
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
    hello(11, 1, 1);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_MODE_PART97, sent(11, OC_CORE_HELLO_ACK)->u.hello_ack.mode);

    /* final review M4: already that mode - no drop (a retried call is harmless) */
    int closed_before = NCLOSED;
    TEST_ASSERT_EQUAL_INT(1, oc_core_cell_mode(&K, 1, OC_SIG_MODE_PART97, NOW));
    TEST_ASSERT_EQUAL_INT(closed_before, NCLOSED);

    TEST_ASSERT_EQUAL_INT(-1, oc_core_cell_mode(&K, 9, OC_SIG_MODE_PART97, NOW)); /* no such cell */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_cell_mode(&K, 1, 7, NOW));                  /* no such mode */
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_revoke(&K, 2, NOW));
    TEST_ASSERT_EQUAL_INT(-3, oc_core_cell_mode(&K, 2, OC_SIG_MODE_PART15, NOW)); /* revoked */
    oc_core_cell_t c;
    TEST_ASSERT_EQUAL_INT(0, ST.cell_get(ST.ctx, 2, &c));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_MODE_PART97, c.mode);
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
    RUN_TEST(test_a_failed_read_refuses_hello_without_a_nak);
    RUN_TEST(test_a_failed_cell_read_adds_nothing);
    RUN_TEST(test_a_failed_list_read_changes_no_list);
    RUN_TEST(test_a_list_that_cant_be_read_at_hello_is_retried_not_dropped);
    RUN_TEST(test_the_fan_out_retries_a_cell_it_cant_read);
    RUN_TEST(test_an_unreadable_list_can_be_replaced);
    RUN_TEST(test_cell_status_is_kept_whole_per_link);
    RUN_TEST(test_a_mode_change_drops_the_link_and_the_next_hello_takes_it);
    return UNITY_END();
}
