/* The cell <-> core protocol codec (network-core spec §6): golden bytes,
 * a round trip of every type, and what must not decode. */
#include "unity.h"

#include <string.h>

#include "lc_core_msg.h"

void setUp(void) {}
void tearDown(void) {}

static void num(const char *text, uint8_t out[LC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT(0, lc_sig_number_to_bcd(text, strlen(text), out));
}

static void golden(const lc_core_msg_t *m, const uint8_t *want, size_t n)
{
    uint8_t buf[LC_CORE_FRAME_MAX];
    lc_core_msg_t back;
    TEST_ASSERT_EQUAL_size_t(n, lc_core_encode(m, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, buf, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_decode(buf, n, &back));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(m, &back, sizeof(back));
}

static void test_golden_bytes(void)
{
    lc_core_msg_t m;

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO;
    m.u.hello.proto = 1;
    m.u.hello.cell_id = 0x01020304u;
    m.u.hello.boot_id = 0x1122334455667788ull;
    m.u.hello.sw_version[1] = 7;
    static const uint8_t hello[] = { 0x00, 0x11, 0x01, 0x01, 0x04, 0x03, 0x02, 0x01, 0x88, 0x77,
                                     0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x07, 0x00 };
    golden(&m, hello, sizeof(hello));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO_ACK;
    m.u.hello_ack.mode = LC_SIG_MODE_PART15;
    m.u.hello_ack.period_s = 1800;
    m.u.hello_ack.key_id = 1;
    num("+883160655500100", m.u.hello_ack.echo_number);
    static const uint8_t ack[] = { 0x00, 0x0E, 0x02, 0x01, 0x08, 0x07, 0x01, 0x00,
                                   0x88, 0x31, 0x60, 0x65, 0x55, 0x00, 0x10, 0x0F };
    golden(&m, ack, sizeof(ack));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = 7;
    num("+883160655501234", m.u.call_route.caller);
    num("+883160655501235", m.u.call_route.called);
    static const uint8_t route[] = { 0x00, 0x15, 0x20, 0x07, 0x00, 0x00, 0x00, 0x88, 0x31, 0x60, 0x65, 0x55,
                                     0x01, 0x23, 0x4F, 0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x5F };
    golden(&m, route, sizeof(route));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_MEDIA;
    m.u.media.ref = LC_CORE_REF_CORE | 1u;
    m.u.media.seq = 0x0102;
    m.u.media.len = 2;
    memcpy(m.u.media.data, "HI", 2);
    static const uint8_t media[] = { 0x00, 0x09, 0x28, 0x01, 0x00, 0x00, 0x80, 0x02, 0x01, 0x48, 0x49 };
    golden(&m, media, sizeof(media));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_RELEASE;
    m.u.call.ref = 7;
    m.u.call.cause = LC_SIG_CAUSE_UNREACHABLE;
    static const uint8_t rel[] = { 0x00, 0x06, 0x24, 0x07, 0x00, 0x00, 0x00, 0x04 };
    golden(&m, rel, sizeof(rel));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_ACT_RES;
    m.u.act_res.req = 0x0102;
    m.u.act_res.tmid = 0x76ad0488u;
    m.u.act_res.msg.type = LC_SIG_ACT_NAK;
    m.u.act_res.msg.u.act_nak.reason = LC_SIG_ACT_USED;
    for (int i = 0; i < 8; i++) m.u.act_res.msg.u.act_nak.tag[i] = (uint8_t)(i + 1);
    static const uint8_t res[] = { 0x00, 0x11, 0x11, 0x02, 0x01, 0x88, 0x04, 0xAD, 0x76, 0x03,
                                   0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    golden(&m, res, sizeof(res));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_RES;
    m.u.av_res.req = 1;
    m.u.av_res.tmid = 0x76ad0488u;
    m.u.av_res.status = LC_CORE_AV_NOT_ACTIVATED; /* no number, no vectors */
    static const uint8_t avres[] = { 0x00, 0x11, 0x13, 0x01, 0x00, 0x88, 0x04, 0xAD, 0x76, 0x01,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    golden(&m, avres, sizeof(avres));

    /* network-core spec §19.1: a vector is RAND 16, AUTN 16, HXRES 16, CK 16,
     * IK 16 - no XRES on the wire */
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_RES;
    m.u.av_res.req = 1;
    m.u.av_res.tmid = 0x76ad0488u;
    m.u.av_res.status = LC_CORE_AV_OK;
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
    m.type = LC_CORE_LOC_CANCEL;
    m.u.loc_cancel.tmid = 0x76ad0488u;
    m.u.loc_cancel.cause = LC_CORE_CANCEL_MOVED;
    static const uint8_t cancel[] = { 0x00, 0x06, 0x1A, 0x88, 0x04, 0xAD, 0x76, 0x01 };
    golden(&m, cancel, sizeof(cancel));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_PING;
    static const uint8_t ping[] = { 0x00, 0x01, 0x04 };
    golden(&m, ping, sizeof(ping));
}

/* Every type once, with every field set: encode, decode, compare. */
static void test_every_type_round_trips(void)
{
    lc_core_msg_t ms[19];
    int k = 0;
    memset(ms, 0, sizeof(ms));
    ms[k].type = LC_CORE_HELLO;
    ms[k].u.hello.proto = 1;
    ms[k].u.hello.cell_id = 9;
    ms[k++].u.hello.boot_id = 0xFEDCBA9876543210ull;
    ms[k].type = LC_CORE_HELLO_ACK;
    ms[k].u.hello_ack.mode = 2;
    num("+883160655500100", ms[k++].u.hello_ack.echo_number);
    ms[k].type = LC_CORE_HELLO_NAK;
    ms[k++].u.hello_nak.reason = LC_CORE_NAK_DISABLED;
    ms[k++].type = LC_CORE_PING;
    ms[k++].type = LC_CORE_PONG;
    ms[k].type = LC_CORE_ACT_FWD;
    ms[k].u.act_fwd.req = 0xBEEF;
    ms[k].u.act_fwd.tmid = 0x11223344u;
    memset(ms[k].u.act_fwd.token_id, 0x01, 8);
    memset(ms[k].u.act_fwd.pkt, 0x02, 32);
    memset(ms[k++].u.act_fwd.tag, 0x03, 8);
    ms[k].type = LC_CORE_ACT_RES;
    ms[k].u.act_res.msg.type = LC_SIG_ACT_ACK;
    num("+883160655501234", ms[k].u.act_res.msg.u.act_ack.number);
    memset(ms[k++].u.act_res.msg.u.act_ack.confirm, 0x44, 8);
    ms[k].type = LC_CORE_AV_REQ;
    ms[k].u.av_req.tmid = 5;
    ms[k++].u.av_req.count = 2;
    ms[k].type = LC_CORE_AV_RES;
    ms[k].u.av_res.status = LC_CORE_AV_OK;
    num("+883160655501234", ms[k].u.av_res.number);
    ms[k].u.av_res.count = LC_CORE_AV_MAX;
    for (unsigned i = 0; i < LC_CORE_AV_MAX; i++) memset(&ms[k].u.av_res.av[i], (int)(0x10 + i), sizeof(lc_core_av_t));
    k++;
    ms[k].type = LC_CORE_RESYNC;
    memset(ms[k].u.resync.rand, 0x55, 16);
    memset(ms[k++].u.resync.auts, 0x66, 14);
    ms[k].type = LC_CORE_LOC_UPDATE;
    ms[k].u.loc_update.tmid = 77;
    num("+883160655501234", ms[k].u.loc_update.number);
    memset(ms[k].u.loc_update.rand, 0x77, 16);
    memset(ms[k++].u.loc_update.res, 0x88, 8);
    ms[k].type = LC_CORE_LOC_PURGE;
    num("+883160655501234", ms[k++].u.loc_purge.number);
    ms[k].type = LC_CORE_LOC_CANCEL;
    ms[k++].u.loc_cancel.cause = LC_CORE_CANCEL_DISABLED;
    ms[k].type = LC_CORE_CALL_ROUTE;
    num("+883160655501234", ms[k].u.call_route.caller);
    num("+883442079460000", ms[k++].u.call_route.called);
    ms[k].type = LC_CORE_CALL_OFFER;
    ms[k].u.call_offer.call_ref = LC_CORE_REF_CORE | 3u;
    num("+883160655501235", ms[k].u.call_offer.callee);
    num("+883160655501234", ms[k++].u.call_offer.caller);
    ms[k].type = LC_CORE_CALL_ALERT;
    ms[k++].u.call.ref = 3;
    ms[k].type = LC_CORE_CALL_ANSWER;
    ms[k++].u.call.ref = 4;
    ms[k].type = LC_CORE_CALL_RELEASE;
    ms[k].u.call.ref = 5;
    ms[k++].u.call.cause = LC_SIG_CAUSE_BUSY;
    ms[k].type = LC_CORE_MEDIA;
    ms[k].u.media.len = LC_SIG_APP_MAX;
    memset(ms[k++].u.media.data, 0x99, LC_SIG_APP_MAX);
    TEST_ASSERT_EQUAL_INT(19, k);
    for (int i = 0; i < k; i++) {
        uint8_t buf[LC_CORE_FRAME_MAX];
        lc_core_msg_t back;
        size_t n = lc_core_encode(&ms[i], buf, sizeof(buf));
        TEST_ASSERT_TRUE_MESSAGE(n >= 3, "encode");
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, lc_core_decode(buf, n, &back), "decode");
        TEST_ASSERT_EQUAL_HEX8_ARRAY(&ms[i], &back, sizeof(back));
        TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&ms[i], buf, n - 1)); /* one byte short */
    }
}

/* §6 frames are at most 512 B: AV_RES with LC_CORE_AV_MAX vectors of 80 B
 * fits (3 + 16 + 4 x 80 = 339). */
static void test_the_largest_av_res_fits_a_frame(void)
{
    lc_core_msg_t m;
    uint8_t buf[LC_CORE_FRAME_MAX + 1];
    TEST_ASSERT_EQUAL_UINT(80, LC_CORE_AV_LEN);
    TEST_ASSERT_EQUAL_UINT(80, sizeof(lc_core_av_t));
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_RES;
    m.u.av_res.status = LC_CORE_AV_OK;
    num("+883160655501234", m.u.av_res.number);
    m.u.av_res.count = LC_CORE_AV_MAX;
    TEST_ASSERT_EQUAL_size_t(3u + 16u + LC_CORE_AV_MAX * LC_CORE_AV_LEN, lc_core_encode(&m, buf, sizeof(buf)));
    TEST_ASSERT_TRUE(3u + 16u + LC_CORE_AV_MAX * LC_CORE_AV_LEN <= LC_CORE_FRAME_MAX);
    size_t n = 3u + 16u + LC_CORE_AV_MAX * LC_CORE_AV_LEN;
    TEST_ASSERT_EQUAL_INT(0, lc_core_decode(buf, n, &m));
    buf[0] = (uint8_t)((n - 3u) >> 8); /* one byte short */
    buf[1] = (uint8_t)(n - 3u);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n - 1u, &m));
    buf[n] = 0; /* one byte over */
    buf[0] = (uint8_t)((n - 1u) >> 8);
    buf[1] = (uint8_t)(n - 1u);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n + 1u, &m));
}

/* The AV_RES format changed with HXRES (network-core spec §19.1), so the
 * protocol version moved to 2 (a proto-1 cell gets HELLO_NAK(version)), and
 * an old-format AV_RES (a 72-byte vector with XRES 8: 91 bytes for one
 * vector) does not decode. */
static void test_proto_2_and_the_old_av_res_does_not_decode(void)
{
    TEST_ASSERT_EQUAL_UINT(2, LC_CORE_PROTO);
    uint8_t old[2 + 1 + 16 + 72];
    static const uint8_t head[] = { 0x00, 0x59, 0x13, 0x01, 0x00, 0x88, 0x04, 0xAD, 0x76, 0x00,
                                    0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x4F, 0x01 };
    TEST_ASSERT_EQUAL_size_t(91, sizeof(old));
    memcpy(old, head, sizeof(head));
    memset(old + sizeof(head), 0x42, sizeof(old) - sizeof(head));
    lc_core_msg_t m;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(old, sizeof(old), &m));
}

static void test_what_does_not_decode(void)
{
    lc_core_msg_t m;
    uint8_t buf[LC_CORE_FRAME_MAX];
    size_t n;

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_ROUTE;
    num("+883160655501234", m.u.call_route.caller);
    num("+883160655501235", m.u.call_route.called);
    n = lc_core_encode(&m, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, lc_core_decode(buf, n, &m));
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n - 1, &m)); /* short */
    buf[1]++;                                                   /* length prefix disagrees */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n, &m));
    buf[1]--;
    buf[n - 1] = 0x5A; /* the called number ends in nibble A: not a number */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n, &m));

    static const uint8_t unknown[] = { 0x00, 0x01, 0x07 }; /* a free type */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(unknown, sizeof(unknown), &m));
    static const uint8_t ping_long[] = { 0x00, 0x02, 0x04, 0x00 };
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(ping_long, sizeof(ping_long), &m));

    memset(&m, 0, sizeof(m)); /* AV_RES with 5 vectors */
    m.type = LC_CORE_AV_RES;
    m.u.av_res.status = LC_CORE_AV_NOT_ACTIVATED;
    m.u.av_res.count = LC_CORE_AV_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&m, buf, sizeof(buf)));
    m.u.av_res.count = 1;
    n = lc_core_encode(&m, buf, sizeof(buf));
    buf[2 + 1 + 2 + 4 + 1 + 8] = 5; /* the count byte */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n, &m));

    memset(&m, 0, sizeof(m)); /* ACT_RES carrying something other than ACT_ACK/NAK */
    m.type = LC_CORE_ACT_RES;
    m.u.act_res.msg.type = LC_SIG_REG_REJ;
    TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&m, buf, sizeof(buf)));

    memset(&m, 0, sizeof(m)); /* MEDIA with 19 bytes */
    m.type = LC_CORE_MEDIA;
    m.u.media.len = LC_SIG_APP_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&m, buf, sizeof(buf)));
    uint8_t big[3 + 4 + 2 + 19] = { 0x00, 3 + 4 + 2 + 19 - 2, LC_CORE_MEDIA };
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(big, sizeof(big), &m));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_golden_bytes);
    RUN_TEST(test_every_type_round_trips);
    RUN_TEST(test_the_largest_av_res_fits_a_frame);
    RUN_TEST(test_proto_2_and_the_old_av_res_does_not_decode);
    RUN_TEST(test_what_does_not_decode);
    return UNITY_END();
}
