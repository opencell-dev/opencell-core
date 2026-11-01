/* Stream channels (streaming channel spec 2026-11-01): a call to a channel
 * rings, opens the stream (the daemon's fetch) only then, answers once the
 * stream plays and 3 s have passed, and sends the daemon's live blocks one
 * per 120 ms in the call's codec; listeners share one opening; the stream
 * closes 5 s after the last listener; a stream that never starts, or fails,
 * gives every listener the offline message once and then cause 0; 1 h at
 * most; and a channel's number is never a subscriber's. */
#include "unity.h"

#include "core_fixture.h"

void setUp(void) {}
void tearDown(void) {}

#define TA       0x0000aaaau
#define TB       0x0000bbbbu
#define LEG      7u
#define LEG_B    8u
#define CH_NUM   "+883160655501021"

/* The offline message: two blocks in Codec2 1200 (0xA1, 0xA2) and OVX-600 (0xB1, 0xB2). */
static uint8_t OFF18[2 * OC_CORE_PLAY_BYTES], OFF9[2 * 9];
static uint8_t NA[OC_SIG_NUMBER_LEN], NB[OC_SIG_NUMBER_LEN], CH[OC_SIG_NUMBER_LEN];

/* The fake daemon: block n of the live stream is byte n (+0x40 in OVX-600). */
static unsigned PULLS, PULLED_BLOCKS, LAST_SKIP;
static uint8_t  LAST_WANT;
static int      PULL_FAIL;

static int f_pull(void *ctx, unsigned ch, uint32_t skip, uint8_t want, uint8_t out[OC_CORE_CLIPS][OC_CORE_PLAY_BYTES])
{
    (void)ctx;
    TEST_ASSERT_EQUAL_UINT(0, ch);
    if (PULL_FAIL) return -1;
    PULLS++;
    PULLED_BLOCKS += skip;
    LAST_SKIP = skip;
    LAST_WANT = want;
    uint8_t n = (uint8_t)PULLED_BLOCKS++;
    if (want & 1u) memset(out[0], n, OC_CORE_PLAY_BYTES);
    if (want & 2u) memset(out[1], (uint8_t)(n + 0x40u), 9);
    return 0;
}

static const oc_core_io_t STREAM_IO = { NULL, f_send, f_close, f_random, f_unix, NULL, f_pull };

static oc_core_cfg_t stream_cfg(void)
{
    oc_core_cfg_t cfg = core_cfg();
    for (unsigned i = 0; i < sizeof(OFF18); i++) OFF18[i] = (uint8_t)(0xA1u + i / OC_CORE_PLAY_BYTES);
    for (unsigned i = 0; i < sizeof(OFF9); i++) OFF9[i] = (uint8_t)(0xB1u + i / 9u);
    number(CH_NUM, cfg.streams[0].number);
    cfg.streams[0].offline[0] = (oc_core_clip_t){ OC_CODEC_C2_1200, OFF18, sizeof(OFF18) };
    cfg.streams[0].offline[1] = (oc_core_clip_t){ OC_CODEC_OVX_600, OFF9, sizeof(OFF9) };
    cfg.streams[0].noffline = 2;
    cfg.nstreams = 1;
    return cfg;
}

static void registered(const char *num, uint8_t out[OC_SIG_NUMBER_LEN], uint32_t tmid, uint32_t cell)
{
    uint8_t got[OC_SIG_NUMBER_LEN];
    oc_core_sub_t s;
    number(num, out);
    TEST_ASSERT_EQUAL_INT(0, oc_core_sub_add(&K, out, got));
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, out, &s));
    s.activated = 1;
    s.tmid = tmid;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    oc_core_loc_t l = { { 0 }, cell, tmid, UNIX0 + 7200u, 0, { 0 } };
    memcpy(l.number, out, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

/* A on cell 1 (link 10), B on cell 2 (link 20); the core has the channel. */
static void stream_world(void)
{
    core_world();
    oc_core_cfg_t cfg = stream_cfg();
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&K, &STREAM_IO, &ST, &RT, &cfg));
    PULLS = PULLED_BLOCKS = LAST_SKIP = 0;
    LAST_WANT = 0;
    PULL_FAIL = 0;
    number(CH_NUM, CH);
    hello(10, 1, 1);
    hello(20, 2, 2);
    registered("+883160655501234", NA, TA, 1);
    registered("+883160655501235", NB, TB, 2);
}

static void route_from(uint32_t link, uint32_t leg, const uint8_t *caller, uint8_t caps)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = leg;
    memcpy(m.u.call_route.caller, caller, OC_SIG_NUMBER_LEN);
    memcpy(m.u.call_route.called, CH, OC_SIG_NUMBER_LEN);
    m.u.call_route.caps = caps;
    rx(link, &m);
}

static void hang_up(uint32_t link, uint32_t leg)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_RELEASE;
    m.u.call.ref = leg;
    rx(link, &m);
}

static void uplink(uint32_t link, uint32_t leg)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_MEDIA;
    m.u.media.ref = leg;
    m.u.media.len = 2;
    rx(link, &m);
}

static int count_since(int from, uint32_t link, uint8_t type)
{
    int n = 0;
    for (int i = from; i < NSENT; i++) n += SENT[i % 128].link == link && SENT[i % 128].m.type == type;
    return n;
}

/* The fake daemon's first second of audio has come. */
static void ready(void) { oc_core_stream_ready(&K, 0, oc_core_stream_wanted(&K, 0), NOW); }

static void test_the_stream_is_closed_until_a_call_and_opened_by_it(void)
{
    stream_world();
    TEST_ASSERT_EQUAL_UINT32(0, oc_core_stream_wanted(&K, 0));
    advance(10000000u); /* (the cells' links die after 15 s of silence) */
    TEST_ASSERT_EQUAL_UINT(0, PULLS);
    int from = NSENT;
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    TEST_ASSERT_NOT_NULL(sent_since(from, 10, OC_CORE_CALL_ALERT)); /* rings at once */
    TEST_ASSERT_EQUAL_UINT32(1, oc_core_stream_wanted(&K, 0));
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_STREAM_CONNECTING, oc_core_stream_state(&K, 0));
    TEST_ASSERT_EQUAL_UINT(1, oc_core_stream_listeners(&K, 0));
}

static void test_answers_after_3_s_once_playing_and_sends_live_blocks(void)
{
    stream_world();
    int from = NSENT;
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    advance(1000000u);
    ready();
    advance(OC_CORE_ECHO_US - 1000000u - 1u);
    TEST_ASSERT_NULL(sent_since(from, 10, OC_CORE_CALL_ANSWER)); /* rings 3 s at least */
    advance(1u);
    const oc_core_msg_t *a = sent_since(from, 10, OC_CORE_CALL_ANSWER);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT8(OC_CODEC_C2_1200, a->u.call.codec);
    TEST_ASSERT_EQUAL_UINT8(0, LAST_WANT); /* pulled while ringing, but encoded for nobody */
    from = NSENT;
    uplink(10, LEG); /* the terminal is connected: the next block goes to it */
    advance(OC_CORE_PLAY_US);
    const oc_core_msg_t *d = sent_since(from, 10, OC_CORE_MEDIA);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT16(0, d->u.media.seq);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_PLAY_BYTES, d->u.media.len);
    TEST_ASSERT_EQUAL_UINT8(1u, LAST_WANT);
    uint8_t first = d->u.media.data[0];
    for (unsigned i = 1; i <= 5; i++) { /* one block every 120 ms, the live point's */
        from = NSENT;
        advance(OC_CORE_PLAY_US);
        TEST_ASSERT_EQUAL_INT(1, count_since(from, 10, OC_CORE_MEDIA));
        d = sent_since(from, 10, OC_CORE_MEDIA);
        TEST_ASSERT_EQUAL_UINT16(i, d->u.media.seq);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(first + i), d->u.media.data[0]);
    }
}

static void test_media_starts_15_s_after_the_answer_without_uplink(void)
{
    stream_world();
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    ready();
    advance(OC_CORE_ECHO_US);
    int from = NSENT;
    advance(OC_CORE_PLAY_LEAD_US - OC_CORE_PLAY_US);
    TEST_ASSERT_EQUAL_INT(0, count_since(from, 10, OC_CORE_MEDIA));
    advance(OC_CORE_PLAY_US);
    TEST_ASSERT_EQUAL_INT(1, count_since(from, 10, OC_CORE_MEDIA));
}

static void test_two_listeners_share_one_opening_each_in_its_codec(void)
{
    stream_world();
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    route_from(20, LEG_B, NB, OC_CODEC_BIT(OC_CODEC_OVX_600));
    TEST_ASSERT_EQUAL_UINT32(1, oc_core_stream_wanted(&K, 0)); /* one opening */
    TEST_ASSERT_EQUAL_UINT(2, oc_core_stream_listeners(&K, 0));
    ready();
    advance(OC_CORE_ECHO_US);
    TEST_ASSERT_EQUAL_UINT8(OC_CODEC_OVX_600, sent(20, OC_CORE_CALL_ANSWER)->u.call.codec);
    uplink(10, LEG);
    uplink(20, LEG_B);
    int from = NSENT;
    advance(OC_CORE_PLAY_US);
    TEST_ASSERT_EQUAL_UINT8(3u, LAST_WANT); /* both codecs, one pull */
    const oc_core_msg_t *a = sent_since(from, 10, OC_CORE_MEDIA), *b = sent_since(from, 20, OC_CORE_MEDIA);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_PLAY_BYTES, a->u.media.len);
    TEST_ASSERT_EQUAL_UINT8(9, b->u.media.len);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(a->u.media.data[0] + 0x40u), b->u.media.data[0]); /* the same block */
}

static void test_a_listener_joining_a_playing_channel_rings_3_s(void)
{
    stream_world();
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    ready();
    advance(OC_CORE_ECHO_US + 10000000u);
    int from = NSENT;
    route_from(20, LEG_B, NB, OC_CODEC_CAPS_DEFAULT);
    TEST_ASSERT_EQUAL_UINT32(1, oc_core_stream_wanted(&K, 0)); /* not reopened */
    advance(OC_CORE_ECHO_US - 1u);
    TEST_ASSERT_NULL(sent_since(from, 20, OC_CORE_CALL_ANSWER));
    advance(1u);
    TEST_ASSERT_NOT_NULL(sent_since(from, 20, OC_CORE_CALL_ANSWER));
}

static void test_closes_5_s_after_the_last_listener_and_reopens_as_a_new_epoch(void)
{
    stream_world();
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    ready();
    advance(OC_CORE_ECHO_US + 2000000u);
    hang_up(10, LEG);
    advance(0u);
    TEST_ASSERT_EQUAL_UINT(0, oc_core_stream_listeners(&K, 0));
    advance(OC_CORE_STREAM_TAIL_US - 1u);
    TEST_ASSERT_EQUAL_UINT32(1, oc_core_stream_wanted(&K, 0)); /* the tail */
    advance(1u);
    TEST_ASSERT_EQUAL_UINT32(0, oc_core_stream_wanted(&K, 0));
    unsigned pulls = PULLS;
    advance(5000000u);
    TEST_ASSERT_EQUAL_UINT(pulls, PULLS); /* nothing pulled while closed */
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    TEST_ASSERT_EQUAL_UINT32(2, oc_core_stream_wanted(&K, 0));
    oc_core_stream_ready(&K, 0, 1, NOW); /* the old fetch's word counts for nothing */
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_STREAM_CONNECTING, oc_core_stream_state(&K, 0));
}

static void test_a_redial_within_the_tail_keeps_the_stream(void)
{
    stream_world();
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    ready();
    advance(OC_CORE_ECHO_US);
    hang_up(10, LEG);
    advance(OC_CORE_STREAM_TAIL_US - 1000000u);
    route_from(10, LEG + 1u, NA, OC_CODEC_CAPS_DEFAULT);
    advance(2000000u);
    TEST_ASSERT_EQUAL_UINT32(1, oc_core_stream_wanted(&K, 0));
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_STREAM_PLAYING, oc_core_stream_state(&K, 0));
}

/* The offline message's blocks reach link `link`, then cause 0. */
static void assert_offline_then_released(int from, uint32_t link, uint8_t b0, uint8_t b1)
{
    for (unsigned i = 0; i < 40 && sent_since(from, link, OC_CORE_CALL_RELEASE) == NULL; i++) advance(OC_CORE_PLAY_US);
    int got = 0;
    for (int i = from; i < NSENT; i++) {
        const sent_t *s = &SENT[i % 128];
        if (s->link != link || s->m.type != OC_CORE_MEDIA) continue;
        if (s->m.u.media.data[0] == b0 || s->m.u.media.data[0] == b1) got++;
    }
    TEST_ASSERT_EQUAL_INT(2, got);
    const oc_core_msg_t *r = sent_since(from, link, OC_CORE_CALL_RELEASE);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NORMAL, r->u.call.cause);
}

static void test_a_stream_that_never_starts_gives_the_offline_message_at_10_s(void)
{
    stream_world();
    int from = NSENT;
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    advance(OC_CORE_STREAM_START_US - 1u);
    TEST_ASSERT_NULL(sent_since(from, 10, OC_CORE_CALL_ANSWER)); /* still ringing while it connects */
    advance(1u);
    TEST_ASSERT_NOT_NULL(sent_since(from, 10, OC_CORE_CALL_ANSWER));
    TEST_ASSERT_EQUAL_UINT32(0, oc_core_stream_wanted(&K, 0)); /* the fetch is stopped */
    assert_offline_then_released(from, 10, 0xA1, 0xA2);
    TEST_ASSERT_EQUAL_UINT(0, PULLS);
}

static void test_a_fetch_that_fails_early_still_rings_3_s_then_the_message(void)
{
    stream_world();
    int from = NSENT;
    route_from(20, LEG_B, NB, OC_CODEC_BIT(OC_CODEC_OVX_600));
    advance(500000u);
    oc_core_stream_failed(&K, 0, 1, "exit 1", NOW);
    advance(OC_CORE_ECHO_US - 500000u - 1u);
    TEST_ASSERT_NULL(sent_since(from, 20, OC_CORE_CALL_ANSWER));
    advance(1u);
    TEST_ASSERT_NOT_NULL(sent_since(from, 20, OC_CORE_CALL_ANSWER));
    assert_offline_then_released(from, 20, 0xB1, 0xB2);
}

static void test_a_mid_call_failure_gives_every_listener_the_message(void)
{
    stream_world();
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    route_from(20, LEG_B, NB, OC_CODEC_BIT(OC_CODEC_OVX_600));
    ready();
    advance(OC_CORE_ECHO_US);
    uplink(10, LEG);
    uplink(20, LEG_B);
    advance(20u * OC_CORE_PLAY_US);
    int from = NSENT;
    PULL_FAIL = 1; /* the daemon: no audio for 5 s */
    advance(OC_CORE_PLAY_US);
    TEST_ASSERT_EQUAL_UINT32(0, oc_core_stream_wanted(&K, 0));
    assert_offline_then_released(from, 10, 0xA1, 0xA2);
    assert_offline_then_released(from, 20, 0xB1, 0xB2);
}

static void test_the_channel_hangs_up_after_1_h(void)
{
    stream_world();
    int from = NSENT;
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    ready();
    advance(OC_CORE_ECHO_US);
    for (unsigned i = 0; i < 3599u; i++) {
        uplink(10, LEG); /* the cell's link stays up */
        advance(1000000u);
    }
    TEST_ASSERT_NULL(sent_since(from, 10, OC_CORE_CALL_RELEASE));
    advance(1000000u);
    const oc_core_msg_t *r = sent_since(from, 10, OC_CORE_CALL_RELEASE);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NORMAL, r->u.call.cause);
}

static void test_a_stall_skips_blocks_rather_than_bursting(void)
{
    stream_world();
    route_from(10, LEG, NA, OC_CODEC_CAPS_DEFAULT);
    ready();
    advance(OC_CORE_ECHO_US);
    uplink(10, LEG);
    advance(OC_CORE_PLAY_US);
    int from = NSENT;
    advance(10u * OC_CORE_PLAY_US); /* the loop stalled 1.2 s */
    TEST_ASSERT_TRUE(count_since(from, 10, OC_CORE_MEDIA) <= 2);
    TEST_ASSERT_TRUE(LAST_SKIP >= 8u); /* the daemon drops the missed audio too */
}

static void test_a_channel_number_is_never_a_subscriber(void)
{
    stream_world();
    uint8_t got[OC_SIG_NUMBER_LEN];
    oc_sig_qr_t qr;
    TEST_ASSERT_TRUE(oc_core_number_service(&K, CH));
    TEST_ASSERT_FALSE(oc_core_number_service(&K, NA));
    TEST_ASSERT_EQUAL_INT(-1, oc_core_sub_add(&K, CH, got));
    TEST_ASSERT_EQUAL_INT(OC_CORE_E_NOT_ASSIGNABLE, oc_core_sub_create(&K, CH, 3600u, &qr));
}

static void test_a_channel_needs_its_offline_message_and_a_pull(void)
{
    core_world();
    oc_core_cfg_t cfg = stream_cfg();
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg)); /* no stream_pull */
    cfg.streams[0].noffline = 0;
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&K, &STREAM_IO, &ST, &RT, &cfg));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_the_stream_is_closed_until_a_call_and_opened_by_it);
    RUN_TEST(test_answers_after_3_s_once_playing_and_sends_live_blocks);
    RUN_TEST(test_media_starts_15_s_after_the_answer_without_uplink);
    RUN_TEST(test_two_listeners_share_one_opening_each_in_its_codec);
    RUN_TEST(test_a_listener_joining_a_playing_channel_rings_3_s);
    RUN_TEST(test_closes_5_s_after_the_last_listener_and_reopens_as_a_new_epoch);
    RUN_TEST(test_a_redial_within_the_tail_keeps_the_stream);
    RUN_TEST(test_a_stream_that_never_starts_gives_the_offline_message_at_10_s);
    RUN_TEST(test_a_fetch_that_fails_early_still_rings_3_s_then_the_message);
    RUN_TEST(test_a_mid_call_failure_gives_every_listener_the_message);
    RUN_TEST(test_the_channel_hangs_up_after_1_h);
    RUN_TEST(test_a_stall_skips_blocks_rather_than_bursting);
    RUN_TEST(test_a_channel_number_is_never_a_subscriber);
    RUN_TEST(test_a_channel_needs_its_offline_message_and_a_pull);
    return UNITY_END();
}
