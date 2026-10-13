/* The playback clip (playback clip spec 2026-10-12 §4): the WAV reader and
 * the Codec2 1200 encoder. The encoder must give c2enc's bytes.
 *   test_oc_clip DATA_DIR */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oc_clip.h"
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
    TEST_ASSERT_TRUE(oc_core_clip_ok(out, OC_CORE_CLIP_MAX));
    free(pcm);
    free(out);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_oc_clip DATA_DIR\n");
        return 2;
    }
    g_data = argv[1];
    UNITY_BEGIN();
    RUN_TEST(test_encoding_gives_c2encs_bytes);
    RUN_TEST(test_a_part_block_is_padded_to_a_whole_payload);
    RUN_TEST(test_a_short_output_buffer_gives_0);
    RUN_TEST(test_ten_minutes_fills_the_clip_exactly);
    return UNITY_END();
}
