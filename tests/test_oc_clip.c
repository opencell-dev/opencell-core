/* The playback clip (playback clip spec 2026-10-12 §4): the WAV reader and
 * the Codec2 1200 encoder. The encoder must give c2enc's bytes.
 *   test_oc_clip DATA_DIR */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oc_clip.h"
#include "oc_codec.h"
#include "oc_core.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static const char *g_data;

/* DATA_DIR/name read whole into a malloc'd buffer; *len its size. */
static uint8_t *slurp(const char *name, size_t *len)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_data, name);
    FILE *f = fopen(path, "rb");
    TEST_ASSERT_NOT_NULL_MESSAGE(f, path);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)sz);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL((size_t)sz, fread(b, 1, (size_t)sz, f));
    fclose(f);
    *len = (size_t)sz;
    return b;
}

static void test_encoding_gives_c2encs_bytes(void)
{
    size_t rlen, blen;
    uint8_t *raw = slurp("clip_fixture.raw", &rlen), *bit = slurp("clip_fixture.bit", &blen);
    int16_t *pcm = malloc(rlen);
    for (size_t i = 0; i < rlen / 2; i++) pcm[i] = (int16_t)(raw[2 * i] | raw[2 * i + 1] << 8);
    uint8_t out[16 * OC_CORE_PLAY_BYTES];
    TEST_ASSERT_EQUAL(blen, oc_clip_encode_c2_1200(pcm, rlen / 2, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(bit, out, blen);
    free(pcm);
    free(raw);
    free(bit);
}

static void test_a_part_block_is_padded_to_a_whole_payload(void)
{
    int16_t pcm[OC_CLIP_BLOCK + 1] = { 0 };
    uint8_t out[3 * OC_CORE_PLAY_BYTES];
    TEST_ASSERT_EQUAL(2 * OC_CORE_PLAY_BYTES, oc_clip_encode_c2_1200(pcm, OC_CLIP_BLOCK + 1, out, sizeof(out)));
    /* Review M5: the padding is silence, not whatever follows pcm[n] */
    int16_t a[2 * OC_CLIP_BLOCK], b[2 * OC_CLIP_BLOCK] = { 0 };
    uint8_t oa[2 * OC_CORE_PLAY_BYTES], ob[2 * OC_CORE_PLAY_BYTES];
    for (size_t i = 0; i < 2 * OC_CLIP_BLOCK; i++) a[i] = (int16_t)(i < OC_CLIP_BLOCK + 1 ? (int)(i % 200) * 60 - 6000 : 12345);
    memcpy(b, a, (OC_CLIP_BLOCK + 1) * sizeof(int16_t)); /* zeros after index OC_CLIP_BLOCK */
    TEST_ASSERT_EQUAL(sizeof(oa), oc_clip_encode_c2_1200(a, OC_CLIP_BLOCK + 1, oa, sizeof(oa)));
    TEST_ASSERT_EQUAL(sizeof(ob), oc_clip_encode_c2_1200(b, 2 * OC_CLIP_BLOCK, ob, sizeof(ob)));
    TEST_ASSERT_EQUAL_MEMORY(ob, oa, sizeof(oa));
    TEST_ASSERT_EQUAL(OC_CORE_PLAY_BYTES, oc_clip_encode_c2_1200(pcm, OC_CLIP_BLOCK, out, sizeof(out)));
}

static void test_a_short_output_buffer_gives_0(void)
{
    int16_t pcm[2 * OC_CLIP_BLOCK] = { 0 };
    uint8_t out[2 * OC_CORE_PLAY_BYTES - 1];
    TEST_ASSERT_EQUAL(0, oc_clip_encode_c2_1200(pcm, 2 * OC_CLIP_BLOCK, out, sizeof(out)));
}

/* Review Focus 3: 10 min is exactly OC_CORE_CLIP_MAX. */
static void test_ten_minutes_fills_the_clip_exactly(void)
{
    int16_t *pcm = calloc(OC_CLIP_MAX_SAMPLES, sizeof(int16_t));
    uint8_t *out = malloc(OC_CORE_CLIP_MAX);
    TEST_ASSERT_EQUAL(OC_CORE_CLIP_MAX, oc_clip_encode_c2_1200(pcm, OC_CLIP_MAX_SAMPLES, out, OC_CORE_CLIP_MAX));
    const oc_core_clip_t c = { OC_CODEC_C2_1200, out, OC_CORE_CLIP_MAX };
    TEST_ASSERT_TRUE(oc_core_clip_ok(&c));
    free(pcm);
    free(out);
}

/* A WAV in b: RIFF, fmt (format, channels, rate, bits), an optional LIST
 * chunk of 3 bytes plus its pad before data, then data of nsamp samples
 * (a ramp). Returns its length. */
static size_t wav(uint8_t *b, uint16_t format, uint16_t ch, uint32_t rate, uint16_t bits, uint32_t nsamp, int list)
{
    size_t o = 0;
    uint32_t data_len = nsamp * ch * (bits / 8u);
#define P4(s) (memcpy(b + o, s, 4), o += 4)
#define U16(v) (b[o] = (uint8_t)(v), b[o + 1] = (uint8_t)((v) >> 8), o += 2)
#define U32(v) (U16((v) & 0xffffu), U16((uint32_t)(v) >> 16))
    P4("RIFF");
    U32(4u + 24u + (list ? 12u : 0u) + 8u + data_len);
    P4("WAVE");
    P4("fmt ");
    U32(16u);
    U16(format);
    U16(ch);
    U32(rate);
    U32(rate * ch * (bits / 8u));
    U16(ch * (bits / 8u));
    U16(bits);
    if (list) {
        P4("LIST");
        U32(3u);
        b[o++] = 'a';
        b[o++] = 'b';
        b[o++] = 'c';
        b[o++] = 0; /* the pad byte */
    }
    P4("data");
    U32(data_len);
    for (uint32_t i = 0; i < data_len / 2u; i++) U16((uint16_t)(int16_t)(i * 7));
#undef P4
#undef U16
#undef U32
    return o;
}

static uint8_t *g_buf; /* big enough for 10 min and a bit */

static void expect_refused(size_t len, const char *reason)
{
    int16_t *pcm = (int16_t *)1;
    size_t n = 99;
    char why[160] = "";
    TEST_ASSERT_EQUAL(-1, oc_wav_read(g_buf, len, &pcm, &n, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, reason), why);
}

static void test_a_good_wav_is_read_with_its_samples(void)
{
    size_t len = wav(g_buf, 1, 1, 8000, 16, 8000, 1);
    int16_t *pcm = NULL;
    size_t n = 0;
    char why[160] = "";
    TEST_ASSERT_EQUAL_MESSAGE(0, oc_wav_read(g_buf, len, &pcm, &n, why, sizeof(why)), why);
    TEST_ASSERT_EQUAL(8000, n);
    TEST_ASSERT_EQUAL_INT16(0, pcm[0]);
    TEST_ASSERT_EQUAL_INT16(7, pcm[1]);
    TEST_ASSERT_EQUAL_INT16((int16_t)(7999 * 7), pcm[7999]);
    free(pcm);
}

static void test_the_wrong_format_is_refused_with_what_it_is(void)
{
    expect_refused(wav(g_buf, 1, 1, 22050, 16, 22050, 0), "22050 Hz, 1 channel, 16-bit, format 1; it must be 8000 Hz mono");
    expect_refused(wav(g_buf, 1, 2, 8000, 16, 8000, 0), "8000 Hz, 2 channels");
    expect_refused(wav(g_buf, 1, 1, 8000, 8, 8000, 0), "8-bit");
    expect_refused(wav(g_buf, 3, 1, 8000, 32, 8000, 0), "format 3");
    /* Review M4a: a bad block align alone names itself, not a contradiction */
    size_t len = wav(g_buf, 1, 1, 8000, 16, 8000, 0);
    g_buf[32] = 4;
    expect_refused(len, "block align 4");
}

/* Review Focus 2 */
static void test_extensible_format_is_refused(void)
{
    expect_refused(wav(g_buf, 0xFFFEu, 1, 8000, 16, 8000, 0), "format 65534");
}

static void test_missing_or_broken_chunks_are_refused(void)
{
    expect_refused(0, "not a RIFF/WAVE file");
    memcpy(g_buf, "RIFX", 4);
    expect_refused(44, "not a RIFF/WAVE file");
    size_t len = wav(g_buf, 1, 1, 8000, 16, 8000, 0);
    expect_refused(36, "no data chunk"); /* RIFF + fmt only */
    memcpy(g_buf + 12, "fmX ", 4);
    expect_refused(len, "no fmt chunk");
    len = wav(g_buf, 1, 1, 8000, 16, 8000, 0);
    g_buf[16] = 14; /* Review M4b: a fmt chunk too short to hold a format */
    expect_refused(34, "a fmt chunk of 14 bytes");
    len = wav(g_buf, 1, 1, 8000, 16, 8000, 0);
    expect_refused(len - 2, "the data chunk runs past the end of the file");
    len = wav(g_buf, 1, 1, 8000, 16, 8000, 0);
    g_buf[40] = (uint8_t)(g_buf[40] - 1u); /* 16000 -> 15999: odd, still inside the file */
    expect_refused(len, "a data chunk of an odd length");
}

/* Review Focus 1: a streaming writer's 0xFFFFFFFF data size */
static void test_streamed_wav_is_refused(void)
{
    size_t len = wav(g_buf, 1, 1, 8000, 16, 8000, 0);
    memset(g_buf + 40, 0xFF, 4);
    expect_refused(len, "the data chunk runs past the end of the file");
}

/* Review Focus 3 */
static void test_one_second_and_ten_minutes_are_accepted(void)
{
    int16_t *pcm = NULL;
    size_t n = 0;
    char why[160] = "";
    size_t len = wav(g_buf, 1, 1, 8000, 16, OC_CLIP_MIN_SAMPLES, 0);
    TEST_ASSERT_EQUAL_MESSAGE(0, oc_wav_read(g_buf, len, &pcm, &n, why, sizeof(why)), why);
    free(pcm);
    len = wav(g_buf, 1, 1, 8000, 16, OC_CLIP_MAX_SAMPLES, 0);
    TEST_ASSERT_EQUAL_MESSAGE(0, oc_wav_read(g_buf, len, &pcm, &n, why, sizeof(why)), why);
    TEST_ASSERT_EQUAL(OC_CLIP_MAX_SAMPLES, n);
    free(pcm);
    expect_refused(wav(g_buf, 1, 1, 8000, 16, OC_CLIP_MIN_SAMPLES - 1u, 0), "0.99 s of audio; it must be 1 s to 10 min");
    expect_refused(wav(g_buf, 1, 1, 8000, 16, OC_CLIP_MAX_SAMPLES + 1u, 0), "600.01 s of audio; it must be 1 s to 10 min"); /* M4c: rounded up, never the limit itself */
}

/* Review Focus 4: an odd last chunk whose pad byte is missing */
static void test_last_odd_chunk_without_pad_is_accepted(void)
{
    size_t len = wav(g_buf, 1, 1, 8000, 16, 8000, 0);
    memcpy(g_buf + len, "LIST", 4);
    g_buf[len + 4] = 3;
    g_buf[len + 5] = g_buf[len + 6] = g_buf[len + 7] = 0;
    memcpy(g_buf + len + 8, "abc", 3); /* no pad byte after it */
    int16_t *pcm = NULL;
    size_t n = 0;
    char why[160] = "";
    TEST_ASSERT_EQUAL_MESSAGE(0, oc_wav_read(g_buf, len + 11, &pcm, &n, why, sizeof(why)), why);
    TEST_ASSERT_EQUAL(8000, n);
    free(pcm);
}

/* OpenVoxNB spec V7 and §5: the fixture's OVX copies are the bytes
 * `oc-vox enc` gives on the same samples (ruling R11). */
static void test_ovx_encoding_gives_oc_vox_enc_bytes(void)
{
    static const struct { uint8_t codec; const char *golden; } k[] = {
        { OC_CODEC_OVX_1200, "clip_fixture.ovx1200" }, { OC_CODEC_OVX_600, "clip_fixture.ovx600" } };
    size_t rlen, glen;
    uint8_t *raw = slurp("clip_fixture.raw", &rlen);
    int16_t *pcm = malloc(rlen);
    for (size_t i = 0; i < rlen / 2; i++) pcm[i] = (int16_t)(raw[2 * i] | raw[2 * i + 1] << 8);
    for (unsigned i = 0; i < 2; i++) {
        uint8_t *g = slurp(k[i].golden, &glen);
        uint8_t out[16 * OC_CORE_PLAY_BYTES];
        TEST_ASSERT_EQUAL(10u * oc_codec_block_bytes(k[i].codec), glen);
        TEST_ASSERT_EQUAL(glen, oc_clip_encode(k[i].codec, pcm, rlen / 2, out, sizeof(out)));
        TEST_ASSERT_EQUAL_MEMORY(g, out, glen);
        free(g);
    }
    free(pcm);
    free(raw);
}

/* Every codec the core serves: one block per 960 samples at its size, the
 * last one padded; a short buffer or a codec with no encoder gives 0. */
static void test_every_served_codec_one_block_per_120_ms(void)
{
    static int16_t pcm[OC_CLIP_BLOCK + 1];
    uint8_t out[2 * OC_CORE_PLAY_BYTES];
    TEST_ASSERT_EQUAL_UINT8(OC_CODEC_C2_1200, oc_clip_codecs[0]); /* admin status names it first */
    for (unsigned i = 0; i < OC_CLIP_CODECS; i++) {
        uint8_t c = oc_clip_codecs[i], b = oc_codec_block_bytes(c);
        TEST_ASSERT_EQUAL(2u * b, oc_clip_encode(c, pcm, OC_CLIP_BLOCK + 1, out, sizeof(out)));
        TEST_ASSERT_EQUAL(0, oc_clip_encode(c, pcm, OC_CLIP_BLOCK + 1, out, 2u * b - 1u));
    }
    TEST_ASSERT_EQUAL(0, oc_clip_encode(OC_CODEC_LPCNET_1733, pcm, OC_CLIP_BLOCK, out, sizeof(out)));
}

/* The live encoder (streaming channel spec §5.2), block after block, gives
 * the bytes the whole-clip encoder gives for the same samples, per codec. */
static void test_the_live_encoder_matches_the_clip_encoder(void)
{
    enum { BLOCKS = 6 };
    static int16_t pcm[BLOCKS * OC_CLIP_BLOCK];
    uint32_t x = 12345u;
    for (unsigned i = 0; i < BLOCKS * OC_CLIP_BLOCK; i++) { /* a noisy tone */
        x = x * 1103515245u + 12345u;
        pcm[i] = (int16_t)((i % 40u < 20u ? 6000 : -6000) + (int)(x >> 20) - 2048);
    }
    for (unsigned c = 0; c < OC_CLIP_CODECS; c++) {
        uint8_t codec = oc_clip_codecs[c], whole[BLOCKS * OC_CORE_PLAY_BYTES], live[BLOCKS * OC_CORE_PLAY_BYTES];
        size_t n = oc_clip_encode(codec, pcm, BLOCKS * OC_CLIP_BLOCK, whole, sizeof(whole)), o = 0;
        oc_clip_enc_t *e = oc_clip_enc_new(codec);
        TEST_ASSERT_NOT_NULL(e);
        for (unsigned b = 0; b < BLOCKS; b++) {
            size_t got = oc_clip_enc_block(e, pcm + b * OC_CLIP_BLOCK, live + o);
            TEST_ASSERT_EQUAL(oc_codec_block_bytes(codec), got);
            o += got;
        }
        oc_clip_enc_free(e);
        TEST_ASSERT_EQUAL(n, o);
        TEST_ASSERT_EQUAL_MEMORY(whole, live, n);
    }
    TEST_ASSERT_NULL(oc_clip_enc_new(OC_CODEC_LPCNET_1733));
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_oc_clip DATA_DIR\n");
        return 2;
    }
    g_data = argv[1];
    g_buf = malloc(2u * OC_CLIP_MAX_SAMPLES + 4096u);
    UNITY_BEGIN();
    RUN_TEST(test_encoding_gives_c2encs_bytes);
    RUN_TEST(test_ovx_encoding_gives_oc_vox_enc_bytes);
    RUN_TEST(test_every_served_codec_one_block_per_120_ms);
    RUN_TEST(test_the_live_encoder_matches_the_clip_encoder);
    RUN_TEST(test_a_part_block_is_padded_to_a_whole_payload);
    RUN_TEST(test_a_short_output_buffer_gives_0);
    RUN_TEST(test_ten_minutes_fills_the_clip_exactly);
    RUN_TEST(test_a_good_wav_is_read_with_its_samples);
    RUN_TEST(test_the_wrong_format_is_refused_with_what_it_is);
    RUN_TEST(test_extensible_format_is_refused);
    RUN_TEST(test_missing_or_broken_chunks_are_refused);
    RUN_TEST(test_streamed_wav_is_refused);
    RUN_TEST(test_one_second_and_ten_minutes_are_accepted);
    RUN_TEST(test_last_odd_chunk_without_pad_is_accepted);
    int rc = UNITY_END();
    free(g_buf);
    return rc;
}
