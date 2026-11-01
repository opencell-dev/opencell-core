/* The playback service (core test services spec §5): it rings and answers
 * like the echo service, then sends its clip to the caller one payload per
 * 120 ms on the core's own clock, in order and looping, starting at the
 * caller's first media or 1.5 s after the answer; skips rather than bursts
 * after a stall; ignores the caller's media; hangs up after 10 min; and a
 * core with no clip has no playback service. */
#include "unity.h"

#include "core_fixture.h"

void setUp(void) {}
void tearDown(void) {}

#define TA       0x0000aaaau
#define LEG      7u
#define PLAY_NUM "+883160655500101"

/* Three payloads, each byte its payload's index + 1; the same three blocks
 * in OVX-600 (9 bytes, 0x91, 0x92, 0x93): the copies of one clip. */
static uint8_t CLIP[3 * OC_CORE_PLAY_BYTES], CLIP9[3 * 9];
static uint8_t NA[OC_SIG_NUMBER_LEN], PLAY[OC_SIG_NUMBER_LEN];

static oc_core_cfg_t play_cfg(void)
{
    oc_core_cfg_t cfg = core_cfg();
    for (unsigned i = 0; i < sizeof(CLIP); i++) CLIP[i] = (uint8_t)(i / OC_CORE_PLAY_BYTES + 1u);
    for (unsigned i = 0; i < sizeof(CLIP9); i++) CLIP9[i] = (uint8_t)(0x91u + i / 9u);
    number(PLAY_NUM, cfg.playback_number);
    cfg.clips[0] = (oc_core_clip_t){ OC_CODEC_C2_1200, CLIP, sizeof(CLIP) };
    cfg.clips[1] = (oc_core_clip_t){ OC_CODEC_OVX_600, CLIP9, sizeof(CLIP9) };
    cfg.nclips = 2;
    return cfg;
}

/* A on cell 1 (link 10), registered; the core has the playback service. */
static void play_world(void)
{
    core_world();
    oc_core_cfg_t cfg = play_cfg();
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    number("+883160655501234", NA);
    number(PLAY_NUM, PLAY);
    hello(10, 1, 1);
    uint8_t got[OC_SIG_NUMBER_LEN];
    oc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, oc_core_sub_add(&K, NA, got));
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, NA, &s));
    s.activated = 1;
    s.tmid = TA;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    oc_core_loc_t l = { { 0 }, 1, TA, UNIX0 + 3600u, 0, { 0 }, 0 };
    memcpy(l.number, NA, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

static void route_caps_to(const uint8_t called[OC_SIG_NUMBER_LEN], uint8_t caps)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = LEG;
    memcpy(m.u.call_route.caller, NA, OC_SIG_NUMBER_LEN);
    memcpy(m.u.call_route.called, called, OC_SIG_NUMBER_LEN);
    m.u.call_route.caps = caps;
    rx(10, &m);
}

static void route_to(const uint8_t called[OC_SIG_NUMBER_LEN]) { route_caps_to(called, OC_CODEC_CAPS_DEFAULT); }

static void uplink(const char *s)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_MEDIA;
    m.u.media.ref = LEG;
    m.u.media.len = (uint8_t)strlen(s);
    memcpy(m.u.media.data, s, m.u.media.len);
    rx(10, &m);
}

static int count_since(int from, uint8_t type)
{
    int n = 0;
    for (int i = from; i < NSENT; i++) n += SENT[i % 128].link == 10 && SENT[i % 128].m.type == type;
    return n;
}

/* Rings, answers after 3 s; returns with NOW at the answer. */
static void answered(void)
{
    int from = NSENT;
    route_to(PLAY);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, OC_CORE_CALL_ALERT)->u.call.ref);
    advance(OC_CORE_ECHO_US - 1u);
    TEST_ASSERT_NULL(sent_since(from, 10, OC_CORE_CALL_ANSWER));
    advance(1u);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, OC_CORE_CALL_ANSWER)->u.call.ref);
}

static void assert_payload(const oc_core_msg_t *d, unsigned index, uint16_t seq)
{
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
    TEST_ASSERT_EQUAL_UINT16(seq, d->u.media.seq);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_PLAY_BYTES, d->u.media.len);
    TEST_ASSERT_EQUAL_MEMORY(CLIP + (index % 3u) * OC_CORE_PLAY_BYTES, d->u.media.data, OC_CORE_PLAY_BYTES);
}

static void test_playback_rings_answers_and_plays_the_clip_in_order(void)
{
    play_world();
    answered();
    int from = NSENT;
    advance(OC_CORE_PLAY_LEAD_US - 1u);
    TEST_ASSERT_EQUAL_INT(0, count_since(from, OC_CORE_MEDIA)); /* the caller's terminal may not be connected yet */
    advance(1u);
    assert_payload(sent_since(from, 10, OC_CORE_MEDIA), 0, 0);
    for (unsigned i = 1; i <= 7; i++) { /* one every 120 ms, looping over the three */
        from = NSENT;
        advance(OC_CORE_PLAY_US - 1u);
        TEST_ASSERT_EQUAL_INT(0, count_since(from, OC_CORE_MEDIA));
        advance(1u);
        TEST_ASSERT_EQUAL_INT(1, count_since(from, OC_CORE_MEDIA));
        assert_payload(sent_since(from, 10, OC_CORE_MEDIA), i, (uint16_t)i);
    }
}

static void test_the_callers_first_media_starts_the_clip_at_once(void)
{
    play_world();
    answered();
    advance(200000u);
    int from = NSENT;
    uplink("UP");
    advance(0u);
    assert_payload(sent_since(from, 10, OC_CORE_MEDIA), 0, 0);
    from = NSENT;
    uplink("UP"); /* later media changes nothing, and is never sent back */
    advance(OC_CORE_PLAY_US);
    TEST_ASSERT_EQUAL_INT(1, count_since(from, OC_CORE_MEDIA));
    assert_payload(sent_since(from, 10, OC_CORE_MEDIA), 1, 1);
}

static void test_a_stall_skips_payloads_and_never_bursts(void)
{
    play_world();
    answered();
    advance(OC_CORE_PLAY_LEAD_US); /* payload 0 */
    int from = NSENT;
    advance(250000u); /* 130 ms late for payload 1: it and payload 2 go, no more */
    TEST_ASSERT_EQUAL_INT(2, count_since(from, OC_CORE_MEDIA));
    assert_payload(sent_since(from, 10, OC_CORE_MEDIA), 2, 2);
    from = NSENT;
    advance(1000000u); /* payload 3 is due at +360 ms: 890 ms late, so 7 are skipped and the 8th goes */
    TEST_ASSERT_EQUAL_INT(1, count_since(from, OC_CORE_MEDIA));
    assert_payload(sent_since(from, 10, OC_CORE_MEDIA), 10, 10);
    TEST_ASSERT_EQUAL_UINT32(7, K.calls[0].play_skipped);
}

static void test_the_caller_hangs_up_and_the_cdr_says_answered(void)
{
    play_world();
    answered();
    advance(OC_CORE_PLAY_LEAD_US + 5u * OC_CORE_PLAY_US);
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_RELEASE;
    m.u.call.ref = LEG;
    m.u.call.cause = OC_SIG_CAUSE_NORMAL;
    rx(10, &m);
    int from = NSENT;
    advance(OC_CORE_PLAY_US * 3u);
    TEST_ASSERT_EQUAL_INT(0, count_since(from, OC_CORE_MEDIA));
    const oc_core_cdr_t *c = &MEM.d.cdr[(MEM.d.ncdr - 1u) % OC_CORE_MEM_LOG];
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PLAY, c->called, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_UINT32(1, c->cell_a);
    TEST_ASSERT_EQUAL_UINT32(0, c->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, c->answer);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NORMAL, c->cause);
}

static void test_the_service_hangs_up_after_10_minutes(void)
{
    play_world();
    answered();
    oc_core_msg_t ping;
    memset(&ping, 0, sizeof(ping));
    ping.type = OC_CORE_PING; /* the cell's link stays up */
    for (uint64_t t = 0; t + 1000000u < OC_CORE_PLAY_MAX_US; t += 1000000u) {
        advance(1000000u);
        rx(10, &ping);
    }
    TEST_ASSERT_EQUAL_UINT32(0, MEM.d.ncdr); /* still playing */
    int from = NSENT;
    advance(1000000u);
    const oc_core_msg_t *r = sent_since(from, 10, OC_CORE_CALL_RELEASE);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NORMAL, r->u.call.cause);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NORMAL, MEM.d.cdr[(MEM.d.ncdr - 1u) % OC_CORE_MEM_LOG].cause);
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, oc_core_due(&K));
}

static void test_the_cell_going_ends_the_playback(void)
{
    play_world();
    answered();
    advance(OC_CORE_PLAY_LEAD_US);
    oc_core_link_down(&K, 10, NOW);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NET_FAILURE, MEM.d.cdr[(MEM.d.ncdr - 1u) % OC_CORE_MEM_LOG].cause);
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, oc_core_due(&K));
}

static void test_due_names_the_next_payload(void)
{
    play_world();
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, oc_core_due(&K));
    route_to(PLAY);
    TEST_ASSERT_EQUAL_UINT64(NOW + OC_CORE_ECHO_US, oc_core_due(&K));
    advance(OC_CORE_ECHO_US);
    TEST_ASSERT_EQUAL_UINT64(NOW + OC_CORE_PLAY_LEAD_US, oc_core_due(&K));
    advance(OC_CORE_PLAY_LEAD_US + 10u);
    TEST_ASSERT_EQUAL_UINT64(NOW - 10u + OC_CORE_PLAY_US, oc_core_due(&K));
}

/* OpenVoxNB spec V7: playback answers with the best codec in the caps it
 * has a copy in (OVX-600 here: there is no OVX-1200 copy) and sends that
 * copy's blocks, at its size, in order, looping, on the same clock. */
static void test_playback_sends_the_copy_for_the_calls_codec(void)
{
    play_world();
    int from = NSENT;
    route_caps_to(PLAY, OC_CODEC_BIT(OC_CODEC_OVX_600) | OC_CODEC_BIT(OC_CODEC_OVX_1200));
    advance(OC_CORE_ECHO_US);
    TEST_ASSERT_EQUAL_UINT8(OC_CODEC_OVX_600, sent_since(from, 10, OC_CORE_CALL_ANSWER)->u.call.codec);
    from = NSENT;
    advance(OC_CORE_PLAY_LEAD_US);
    for (unsigned i = 0; i < 4; i++) {
        const oc_core_msg_t *d = sent_since(from, 10, OC_CORE_MEDIA);
        TEST_ASSERT_NOT_NULL(d);
        TEST_ASSERT_EQUAL_UINT16(i, d->u.media.seq);
        TEST_ASSERT_EQUAL_UINT8(9, d->u.media.len);
        TEST_ASSERT_EQUAL_MEMORY(CLIP9 + (i % 3u) * 9u, d->u.media.data, 9);
        from = NSENT;
        advance(OC_CORE_PLAY_US);
    }
}

/* §6.3: caps with no copy (LPCNet only) end the call before it rings, cause 7. */
static void test_caps_with_no_copy_get_cause_7(void)
{
    play_world();
    int from = NSENT;
    route_caps_to(PLAY, OC_CODEC_BIT(OC_CODEC_LPCNET_1733));
    TEST_ASSERT_NULL(sent_since(from, 10, OC_CORE_CALL_ALERT));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_NO_CODEC, sent_since(from, 10, OC_CORE_CALL_RELEASE)->u.call.cause);
}

static void test_no_clip_no_playback_service(void)
{
    oc_core_cfg_t cfg = play_cfg();
    core_world();
    cfg.clips[0].len = OC_CORE_PLAY_BYTES - 1u; /* not a whole payload */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    cfg = play_cfg();
    cfg.clips[1].len = 2u * 9u; /* the copies disagree on the clip's length */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    cfg = play_cfg();
    cfg.clips[1] = cfg.clips[0]; /* one codec twice */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    cfg = play_cfg();
    cfg.nclips = 0;
    TEST_ASSERT_EQUAL_INT(-1, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    const oc_core_clip_t too_long = { OC_CODEC_C2_1200, CLIP, OC_CORE_CLIP_MAX + OC_CORE_PLAY_BYTES };
    const oc_core_clip_t one = { OC_CODEC_C2_1200, CLIP, OC_CORE_PLAY_BYTES };
    const oc_core_clip_t ovx = { OC_CODEC_OVX_600, CLIP9, 9 };
    const oc_core_clip_t ovx_cut = { OC_CODEC_OVX_600, CLIP9, 10 };
    const oc_core_clip_t lpcnet = { OC_CODEC_LPCNET_1733, CLIP, OC_CORE_PLAY_BYTES };
    TEST_ASSERT_FALSE(oc_core_clip_ok(&too_long));
    TEST_ASSERT_TRUE(oc_core_clip_ok(&one));
    TEST_ASSERT_TRUE(oc_core_clip_ok(&ovx));
    TEST_ASSERT_FALSE(oc_core_clip_ok(&ovx_cut));
    TEST_ASSERT_FALSE(oc_core_clip_ok(&lpcnet)); /* no block size: no copy of it */
    /* the playback number unset: a call to 00101 is a call to a reserved number, unreachable */
    play_world();
    cfg = core_cfg();
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    hello(10, 1, 1);
    oc_core_loc_t l = { { 0 }, 1, TA, UNIX0 + 3600u, 0, { 0 }, 0 };
    memcpy(l.number, NA, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
    int from = NSENT;
    route_to(PLAY);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_UNREACHABLE, sent_since(from, 10, OC_CORE_CALL_RELEASE)->u.call.cause);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_playback_rings_answers_and_plays_the_clip_in_order);
    RUN_TEST(test_the_callers_first_media_starts_the_clip_at_once);
    RUN_TEST(test_a_stall_skips_payloads_and_never_bursts);
    RUN_TEST(test_the_caller_hangs_up_and_the_cdr_says_answered);
    RUN_TEST(test_the_service_hangs_up_after_10_minutes);
    RUN_TEST(test_the_cell_going_ends_the_playback);
    RUN_TEST(test_due_names_the_next_payload);
    RUN_TEST(test_playback_sends_the_copy_for_the_calls_codec);
    RUN_TEST(test_caps_with_no_copy_get_cause_7);
    RUN_TEST(test_no_clip_no_playback_service);
    return UNITY_END();
}
