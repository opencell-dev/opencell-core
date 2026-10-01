/* The cell <-> core protocol codec (network-core spec §6): golden bytes,
 * a round trip of every type, and what must not decode. */
#include "unity.h"

#include <string.h>

#include "oc_core_msg.h"

void setUp(void) {}
void tearDown(void) {}

static void num(const char *text, uint8_t out[OC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(text, strlen(text), out));
}

static void golden(const oc_core_msg_t *m, const uint8_t *want, size_t n)
{
    uint8_t buf[OC_CORE_FRAME_MAX];
    oc_core_msg_t back;
    TEST_ASSERT_EQUAL_size_t(n, oc_core_encode(m, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, buf, n);
    TEST_ASSERT_EQUAL_INT(0, oc_core_decode(buf, n, &back));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(m, &back, sizeof(back));
}

static void test_golden_bytes(void)
{
    oc_core_msg_t m;

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_HELLO;
    m.u.hello.proto = 1;
    m.u.hello.cell_id = 0x01020304u;
    m.u.hello.boot_id = 0x1122334455667788ull;
    m.u.hello.sw_version[1] = 7;
    static const uint8_t hello[] = { 0x00, 0x11, 0x01, 0x01, 0x04, 0x03, 0x02, 0x01, 0x88, 0x77,
                                     0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x07, 0x00 };
    golden(&m, hello, sizeof(hello));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_HELLO_ACK;
    m.u.hello_ack.mode = OC_SIG_MODE_PART15;
    m.u.hello_ack.period_s = 1800;
    m.u.hello_ack.key_id = 1;
    num("+883160655500100", m.u.hello_ack.echo_number);
    static const uint8_t ack[] = { 0x00, 0x0E, 0x02, 0x01, 0x08, 0x07, 0x01, 0x00,
                                   0x88, 0x31, 0x60, 0x65, 0x55, 0x00, 0x10, 0x0F };
    golden(&m, ack, sizeof(ack));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = 7;
    num("+883160655501234", m.u.call_route.caller);
    num("+883160655501235", m.u.call_route.called);
    static const uint8_t route[] = { 0x00, 0x15, 0x20, 0x07, 0x00, 0x00, 0x00, 0x88, 0x31, 0x60, 0x65, 0x55,
                                     0x01, 0x23, 0x4F, 0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x5F };
    golden(&m, route, sizeof(route));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_MEDIA;
    m.u.media.ref = OC_CORE_REF_CORE | 1u;
    m.u.media.seq = 0x0102;
    m.u.media.len = 2;
    memcpy(m.u.media.data, "HI", 2);
    static const uint8_t media[] = { 0x00, 0x09, 0x28, 0x01, 0x00, 0x00, 0x80, 0x02, 0x01, 0x48, 0x49 };
    golden(&m, media, sizeof(media));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_RELEASE;
    m.u.call.ref = 7;
    m.u.call.cause = OC_SIG_CAUSE_UNREACHABLE;
    static const uint8_t rel[] = { 0x00, 0x06, 0x24, 0x07, 0x00, 0x00, 0x00, 0x04 };
    golden(&m, rel, sizeof(rel));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_ACT_RES;
    m.u.act_res.req = 0x0102;
    m.u.act_res.tmid = 0x76ad0488u;
    m.u.act_res.msg.type = OC_SIG_ACT_NAK;
    m.u.act_res.msg.u.act_nak.reason = OC_SIG_ACT_USED;
    for (int i = 0; i < 8; i++) m.u.act_res.msg.u.act_nak.tag[i] = (uint8_t)(i + 1);
    static const uint8_t res[] = { 0x00, 0x11, 0x11, 0x02, 0x01, 0x88, 0x04, 0xAD, 0x76, 0x03,
                                   0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    golden(&m, res, sizeof(res));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_AV_RES;
    m.u.av_res.req = 1;
    m.u.av_res.tmid = 0x76ad0488u;
    m.u.av_res.status = OC_CORE_AV_NOT_ACTIVATED; /* no number, no vectors */
    static const uint8_t avres[] = { 0x00, 0x11, 0x13, 0x01, 0x00, 0x88, 0x04, 0xAD, 0x76, 0x01,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    golden(&m, avres, sizeof(avres));

    /* network-core spec §19.1: a vector is RAND 16, AUTN 16, HXRES 16, CK 16,
     * IK 16 - no XRES on the wire */
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_AV_RES;
    m.u.av_res.req = 1;
    m.u.av_res.tmid = 0x76ad0488u;
    m.u.av_res.status = OC_CORE_AV_OK;
    num("+883160655501234", m.u.av_res.number);
    m.u.av_res.count = 1;
    memset(m.u.av_res.av[0].rand, 0x01, 16);
    memset(m.u.av_res.av[0].autn, 0x02, 16);
    memset(m.u.av_res.av[0].hxres, 0x03, 16);
    memset(m.u.av_res.av[0].ck, 0x04, 16);
    memset(m.u.av_res.av[0].ik, 0x05, 16);
    uint8_t avok[2 + 1 + 16 + 80];
    static const uint8_t avok_head[] = { 0x00, 0x61, 0x13, 0x01, 0x00, 0x88, 0x04, 0xAD, 0x76, 0x00,
                                         0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x4F, 0x01 };
    memcpy(avok, avok_head, sizeof(avok_head));
    for (int f = 0; f < 5; f++) memset(avok + sizeof(avok_head) + 16 * f, f + 1, 16);
    golden(&m, avok, sizeof(avok));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_LOC_CANCEL;
    m.u.loc_cancel.tmid = 0x76ad0488u;
    m.u.loc_cancel.cause = OC_CORE_CANCEL_MOVED;
    memset(m.u.loc_cancel.rand, 0x5c, 16); /* the RAND that proved the location cancelled */
    uint8_t cancel[2 + 1 + 5 + 16];
    static const uint8_t cancel_head[] = { 0x00, 0x16, 0x1A, 0x88, 0x04, 0xAD, 0x76, 0x01 };
    memcpy(cancel, cancel_head, sizeof(cancel_head));
    memset(cancel + sizeof(cancel_head), 0x5c, 16);
    golden(&m, cancel, sizeof(cancel));

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_PING;
    static const uint8_t ping[] = { 0x00, 0x01, 0x04 };
    golden(&m, ping, sizeof(ping));
}

/* Every type once, with every field set: encode, decode, compare. */
static void test_every_type_round_trips(void)
{
    oc_core_msg_t ms[19];
    int k = 0;
    memset(ms, 0, sizeof(ms));
    ms[k].type = OC_CORE_HELLO;
    ms[k].u.hello.proto = 1;
    ms[k].u.hello.cell_id = 9;
    ms[k++].u.hello.boot_id = 0xFEDCBA9876543210ull;
    ms[k].type = OC_CORE_HELLO_ACK;
    ms[k].u.hello_ack.mode = 2;
    num("+883160655500100", ms[k++].u.hello_ack.echo_number);
    ms[k].type = OC_CORE_HELLO_NAK;
    ms[k++].u.hello_nak.reason = OC_CORE_NAK_DISABLED;
    ms[k++].type = OC_CORE_PING;
    ms[k++].type = OC_CORE_PONG;
    ms[k].type = OC_CORE_ACT_FWD;
    ms[k].u.act_fwd.req = 0xBEEF;
    ms[k].u.act_fwd.tmid = 0x11223344u;
    memset(ms[k].u.act_fwd.token_id, 0x01, 8);
    memset(ms[k].u.act_fwd.pkt, 0x02, 32);
    memset(ms[k++].u.act_fwd.tag, 0x03, 8);
    ms[k].type = OC_CORE_ACT_RES;
    ms[k].u.act_res.msg.type = OC_SIG_ACT_ACK;
    num("+883160655501234", ms[k].u.act_res.msg.u.act_ack.number);
    memset(ms[k++].u.act_res.msg.u.act_ack.confirm, 0x44, 8);
    ms[k].type = OC_CORE_AV_REQ;
    ms[k].u.av_req.tmid = 5;
    ms[k++].u.av_req.count = 2;
    ms[k].type = OC_CORE_AV_RES;
    ms[k].u.av_res.status = OC_CORE_AV_OK;
    num("+883160655501234", ms[k].u.av_res.number);
    ms[k].u.av_res.count = OC_CORE_AV_MAX;
    for (unsigned i = 0; i < OC_CORE_AV_MAX; i++) memset(&ms[k].u.av_res.av[i], (int)(0x10 + i), sizeof(oc_core_av_t));
    k++;
    ms[k].type = OC_CORE_RESYNC;
    memset(ms[k].u.resync.rand, 0x55, 16);
    memset(ms[k++].u.resync.auts, 0x66, 14);
    ms[k].type = OC_CORE_LOC_UPDATE;
    ms[k].u.loc_update.tmid = 77;
    num("+883160655501234", ms[k].u.loc_update.number);
    memset(ms[k].u.loc_update.rand, 0x77, 16);
    memset(ms[k++].u.loc_update.res, 0x88, 8);
    ms[k].type = OC_CORE_LOC_PURGE;
    num("+883160655501234", ms[k++].u.loc_purge.number);
    ms[k].type = OC_CORE_LOC_CANCEL;
    ms[k].u.loc_cancel.cause = OC_CORE_CANCEL_DISABLED;
    memset(ms[k++].u.loc_cancel.rand, 0x99, 16);
    ms[k].type = OC_CORE_CALL_ROUTE;
    num("+883160655501234", ms[k].u.call_route.caller);
    num("+883442079460000", ms[k++].u.call_route.called);
    ms[k].type = OC_CORE_CALL_OFFER;
    ms[k].u.call_offer.call_ref = OC_CORE_REF_CORE | 3u;
    num("+883160655501235", ms[k].u.call_offer.callee);
    num("+883160655501234", ms[k++].u.call_offer.caller);
    ms[k].type = OC_CORE_CALL_ALERT;
    ms[k++].u.call.ref = 3;
    ms[k].type = OC_CORE_CALL_ANSWER;
    ms[k++].u.call.ref = 4;
    ms[k].type = OC_CORE_CALL_RELEASE;
    ms[k].u.call.ref = 5;
    ms[k++].u.call.cause = OC_SIG_CAUSE_BUSY;
    ms[k].type = OC_CORE_MEDIA;
    ms[k].u.media.len = OC_SIG_APP_MAX;
    memset(ms[k++].u.media.data, 0x99, OC_SIG_APP_MAX);
    TEST_ASSERT_EQUAL_INT(19, k);
    for (int i = 0; i < k; i++) {
        uint8_t buf[OC_CORE_FRAME_MAX];
        oc_core_msg_t back;
        size_t n = oc_core_encode(&ms[i], buf, sizeof(buf));
        TEST_ASSERT_TRUE_MESSAGE(n >= 3, "encode");
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_core_decode(buf, n, &back), "decode");
        TEST_ASSERT_EQUAL_HEX8_ARRAY(&ms[i], &back, sizeof(back));
        TEST_ASSERT_EQUAL_size_t(0, oc_core_encode(&ms[i], buf, n - 1)); /* one byte short */
    }
}

/* §6 frames are at most 512 B: AV_RES with OC_CORE_AV_MAX vectors of 80 B
 * fits (3 + 16 + 4 x 80 = 339). */
static void test_the_largest_av_res_fits_a_frame(void)
{
    oc_core_msg_t m;
    uint8_t buf[OC_CORE_FRAME_MAX + 1];
    TEST_ASSERT_EQUAL_UINT(80, OC_CORE_AV_LEN);
    TEST_ASSERT_EQUAL_UINT(80, sizeof(oc_core_av_t));
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_AV_RES;
    m.u.av_res.status = OC_CORE_AV_OK;
    num("+883160655501234", m.u.av_res.number);
    m.u.av_res.count = OC_CORE_AV_MAX;
    TEST_ASSERT_EQUAL_size_t(3u + 16u + OC_CORE_AV_MAX * OC_CORE_AV_LEN, oc_core_encode(&m, buf, sizeof(buf)));
    TEST_ASSERT_TRUE(3u + 16u + OC_CORE_AV_MAX * OC_CORE_AV_LEN <= OC_CORE_FRAME_MAX);
    size_t n = 3u + 16u + OC_CORE_AV_MAX * OC_CORE_AV_LEN;
    TEST_ASSERT_EQUAL_INT(0, oc_core_decode(buf, n, &m));
    buf[0] = (uint8_t)((n - 3u) >> 8); /* one byte short */
    buf[1] = (uint8_t)(n - 3u);
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(buf, n - 1u, &m));
    buf[n] = 0; /* one byte over */
    buf[0] = (uint8_t)((n - 1u) >> 8);
    buf[1] = (uint8_t)(n - 1u);
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(buf, n + 1u, &m));
}

/* The AV_RES format changed with HXRES (network-core spec §19.1), so the
 * protocol version moved to 2 (a proto-1 cell gets HELLO_NAK(version)), and
 * an old-format AV_RES (a 72-byte vector with XRES 8: 91 bytes for one
 * vector) does not decode. */
static void test_proto_2_and_the_old_av_res_does_not_decode(void)
{
    TEST_ASSERT_EQUAL_UINT(2, OC_CORE_PROTO);
    uint8_t old[2 + 1 + 16 + 72];
    static const uint8_t head[] = { 0x00, 0x59, 0x13, 0x01, 0x00, 0x88, 0x04, 0xAD, 0x76, 0x00,
                                    0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x4F, 0x01 };
    TEST_ASSERT_EQUAL_size_t(91, sizeof(old));
    memcpy(old, head, sizeof(head));
    memset(old + sizeof(head), 0x42, sizeof(old) - sizeof(head));
    oc_core_msg_t m;
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(old, sizeof(old), &m));
}

static void test_what_does_not_decode(void)
{
    oc_core_msg_t m;
    uint8_t buf[OC_CORE_FRAME_MAX];
    size_t n;

    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_ROUTE;
    num("+883160655501234", m.u.call_route.caller);
    num("+883160655501235", m.u.call_route.called);
    n = oc_core_encode(&m, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, oc_core_decode(buf, n, &m));
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(buf, n - 1, &m)); /* short */
    buf[1]++;                                                   /* length prefix disagrees */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(buf, n, &m));
    buf[1]--;
    buf[n - 1] = 0x5A; /* the called number ends in nibble A: not a number */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(buf, n, &m));

    static const uint8_t unknown[] = { 0x00, 0x01, 0x07 }; /* a free type */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(unknown, sizeof(unknown), &m));
    static const uint8_t ping_long[] = { 0x00, 0x02, 0x04, 0x00 };
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(ping_long, sizeof(ping_long), &m));

    memset(&m, 0, sizeof(m)); /* AV_RES with 5 vectors */
    m.type = OC_CORE_AV_RES;
    m.u.av_res.status = OC_CORE_AV_NOT_ACTIVATED;
    m.u.av_res.count = OC_CORE_AV_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, oc_core_encode(&m, buf, sizeof(buf)));
    m.u.av_res.count = 1;
    n = oc_core_encode(&m, buf, sizeof(buf));
    buf[2 + 1 + 2 + 4 + 1 + 8] = 5; /* the count byte */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(buf, n, &m));

    memset(&m, 0, sizeof(m)); /* ACT_RES carrying something other than ACT_ACK/NAK */
    m.type = OC_CORE_ACT_RES;
    m.u.act_res.msg.type = OC_SIG_REG_REJ;
    TEST_ASSERT_EQUAL_size_t(0, oc_core_encode(&m, buf, sizeof(buf)));

    memset(&m, 0, sizeof(m)); /* MEDIA with 19 bytes */
    m.type = OC_CORE_MEDIA;
    m.u.media.len = OC_SIG_APP_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, oc_core_encode(&m, buf, sizeof(buf)));
    uint8_t big[3 + 4 + 2 + 19] = { 0x00, 3 + 4 + 2 + 19 - 2, OC_CORE_MEDIA };
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(big, sizeof(big), &m));
}

/* CELL_CFG carries a CHAN_LIST body exactly as oc_sig encodes it:
 * ver, count, then count x { freq_hz (big-endian, as in oc_sig), flags }. */
static void test_cell_cfg(void)
{
    oc_core_msg_t m, back;
    uint8_t buf[OC_CORE_FRAME_MAX];
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CELL_CFG;
    m.u.cell_cfg.list.ver = 1;
    m.u.cell_cfg.list.count = 2;
    m.u.cell_cfg.list.freq_hz[0] = 917250000u;
    m.u.cell_cfg.list.freq_hz[1] = 922250000u;
    m.u.cell_cfg.list.flags[1] = OC_SIG_CHAN_FIXED;
    static const uint8_t cfg[] = { 0x00, 0x0D, 0x06, 0x01, 0x02, 0x36, 0xAC, 0x1F, 0xD0, 0x00,
                                   0x36, 0xF8, 0x6B, 0x10, 0x01 };
    golden(&m, cfg, sizeof(cfg));

    memset(&m, 0, sizeof(m)); /* no entries: the group's list was emptied */
    m.type = OC_CORE_CELL_CFG;
    m.u.cell_cfg.list.ver = 9;
    static const uint8_t empty[] = { 0x00, 0x03, 0x06, 0x09, 0x00 };
    golden(&m, empty, sizeof(empty));

    m.u.cell_cfg.list.count = OC_SIG_CHAN_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, oc_core_encode(&m, buf, sizeof(buf)));
    static const uint8_t cut[] = { 0x00, 0x07, 0x06, 0x01, 0x01, 0x36, 0xAC, 0x1F, 0xD0 }; /* no flags byte */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(cut, sizeof(cut), &back));
}

/* OCSS (core test services spec §6): the link and call-control frames. */
static void test_ocss_golden_bytes(void)
{
    oc_core_msg_t m;

    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_HELLO;
    m.u.peer_hello.proto = OC_OCSS_PROTO;
    m.u.peer_hello.core_id = 0x0102;
    m.u.peer_hello.table_ver = 0x03040506u;
    static const uint8_t hello[] = { 0x00, 0x08, 0x41, 0x01, 0x02, 0x01, 0x06, 0x05, 0x04, 0x03 };
    golden(&m, hello, sizeof(hello));

    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_HELLO_ACK;
    m.u.peer_hello.core_id = 2;
    static const uint8_t ack[] = { 0x00, 0x07, 0x42, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    golden(&m, ack, sizeof(ack));

    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_HELLO_NAK;
    m.u.hello_nak.reason = OC_OCSS_NAK_WRONG_CORE;
    static const uint8_t nak[] = { 0x00, 0x02, 0x43, 0x01 };
    golden(&m, nak, sizeof(nak));

    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_PING;
    static const uint8_t ping[] = { 0x00, 0x01, 0x44 };
    golden(&m, ping, sizeof(ping));

    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_CALL_SETUP;
    m.u.setup.call_ref = OC_CORE_REF_CORE | 1u;
    num("+883160655501234", m.u.setup.caller);
    num("+883150355500101", m.u.setup.called);
    static const uint8_t setup[] = { 0x00, 0x16, 0x60, 0x01, 0x00, 0x00, 0x80, 0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23,
                                     0x4F, 0x88, 0x31, 0x50, 0x35, 0x55, 0x00, 0x10, 0x1F, 0x00 };
    golden(&m, setup, sizeof(setup));

    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_CALL_RELEASE;
    m.u.call.ref = OC_CORE_REF_CORE | 1u;
    m.u.call.cause = OC_SIG_CAUSE_NET_FAILURE;
    static const uint8_t rel[] = { 0x00, 0x06, 0x64, 0x01, 0x00, 0x00, 0x80, 0x05 };
    golden(&m, rel, sizeof(rel));

    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_MEDIA;
    m.u.media.ref = OC_CORE_REF_CORE | 1u;
    m.u.media.seq = 0x0102;
    m.u.media.len = 2;
    memcpy(m.u.media.data, "HI", 2);
    static const uint8_t media[] = { 0x00, 0x09, 0x68, 0x01, 0x00, 0x00, 0x80, 0x02, 0x01, 0x48, 0x49 };
    golden(&m, media, sizeof(media));

    static const uint8_t types[] = { OC_OCSS_PONG, OC_OCSS_CALL_ALERT, OC_OCSS_CALL_ANSWER };
    for (unsigned i = 0; i < sizeof(types); i++) { /* the rest round-trip */
        uint8_t buf[OC_CORE_FRAME_MAX];
        oc_core_msg_t back;
        memset(&m, 0, sizeof(m));
        m.type = types[i];
        m.u.call.ref = types[i] == OC_OCSS_PONG ? 0 : 9;
        size_t n = oc_core_encode(&m, buf, sizeof(buf));
        TEST_ASSERT_NOT_EQUAL(0, n);
        TEST_ASSERT_EQUAL_INT(0, oc_core_decode(buf, n, &back));
        TEST_ASSERT_EQUAL_HEX8_ARRAY(&m, &back, sizeof(back));
    }
}

static void test_ocss_what_does_not_decode(void)
{
    oc_core_msg_t m;
    static const uint8_t short_hello[] = { 0x00, 0x07, 0x41, 0x01, 0x02, 0x01, 0x06, 0x05, 0x04 };
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(short_hello, sizeof(short_hello), &m));
    static const uint8_t long_ack[] = { 0x00, 0x08, 0x42, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(long_ack, sizeof(long_ack), &m));
    static const uint8_t bad_called[] = { 0x00, 0x16, 0x60, 0x01, 0x00, 0x00, 0x80, 0x88, 0x31, 0x60, 0x65, 0x55, 0x01,
                                          0x23, 0x4F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(bad_called, sizeof(bad_called), &m));
    uint8_t big[2 + 1 + 4 + 2 + OC_SIG_APP_MAX + 1] = { 0x00, sizeof(big) - 2u, OC_OCSS_MEDIA };
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(big, sizeof(big), &m));
    static const uint8_t free_type[] = { 0x00, 0x01, 0x46 }; /* kept for routing (plan 10): not this build's */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_decode(free_type, sizeof(free_type), &m));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_golden_bytes);
    RUN_TEST(test_every_type_round_trips);
    RUN_TEST(test_the_largest_av_res_fits_a_frame);
    RUN_TEST(test_proto_2_and_the_old_av_res_does_not_decode);
    RUN_TEST(test_what_does_not_decode);
    RUN_TEST(test_cell_cfg);
    RUN_TEST(test_ocss_golden_bytes);
    RUN_TEST(test_ocss_what_does_not_decode);
    return UNITY_END();
}
