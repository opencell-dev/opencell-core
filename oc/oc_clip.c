/* The playback clip (playback clip spec 2026-10-12 §4): the WAV reader and
 * the Codec2 1200 encoder. */
#include "oc_clip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec2.h"
#include "oc_core.h"

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)le16(p) | (uint32_t)le16(p + 2) << 16; }

int oc_wav_read(const uint8_t *buf, size_t len, int16_t **pcm, size_t *n, char *why, size_t why_len)
{
    if (len < 12 || memcmp(buf, "RIFF", 4) != 0 || memcmp(buf + 8, "WAVE", 4) != 0) {
        snprintf(why, why_len, "not a RIFF/WAVE file");
        return -1;
    }
    const uint8_t *fmt = NULL, *data = NULL;
    uint32_t fmt_len = 0, data_len = 0;
    for (size_t off = 12; off + 8 <= len;) { /* chunks, word-aligned */
        uint32_t sz = le32(buf + off + 4);
        int is_data = memcmp(buf + off, "data", 4) == 0;
        if (sz > len - off - 8) {
            snprintf(why, why_len, is_data ? "the data chunk runs past the end of the file"
                                           : "a chunk runs past the end of the file");
            return -1;
        }
        if (memcmp(buf + off, "fmt ", 4) == 0) {
            fmt = buf + off + 8;
            fmt_len = sz;
        } else if (is_data) {
            data = buf + off + 8;
            data_len = sz;
        }
        off += 8u + (size_t)sz + (sz & 1u); /* a missing last pad byte ends the loop */
    }
    if (fmt == NULL || fmt_len < 16) {
        snprintf(why, why_len, "no fmt chunk");
        return -1;
    }
    if (data == NULL) {
        snprintf(why, why_len, "no data chunk");
        return -1;
    }
    unsigned format = le16(fmt), ch = le16(fmt + 2), bits = le16(fmt + 14);
    uint32_t rate = le32(fmt + 4);
    if (format != 1 || ch != 1 || rate != OC_CLIP_RATE || bits != 16 || le16(fmt + 12) != 2) {
        snprintf(why, why_len, "%u Hz, %u channels, %u-bit, format %u; it must be 8000 Hz mono 16-bit PCM (format 1)",
                 (unsigned)rate, ch, bits, format);
        return -1;
    }
    if (data_len & 1u) {
        snprintf(why, why_len, "a data chunk of an odd length");
        return -1;
    }
    size_t samples = data_len / 2u;
    if (samples < OC_CLIP_MIN_SAMPLES || samples > OC_CLIP_MAX_SAMPLES) {
        size_t cs = samples / 80u; /* hundredths of a second, rounded down */
        snprintf(why, why_len, "%u.%02u s of audio; it must be 1 s to 10 min", (unsigned)(cs / 100u),
                 (unsigned)(cs % 100u));
        return -1;
    }
    int16_t *p = malloc(samples * sizeof(int16_t));
    if (p == NULL) {
        snprintf(why, why_len, "out of memory for %zu samples", samples);
        return -1;
    }
    for (size_t i = 0; i < samples; i++) p[i] = (int16_t)le16(data + 2 * i);
    *pcm = p;
    *n = samples;
    return 0;
}

size_t oc_clip_encode_c2_1200(const int16_t *pcm, size_t n, uint8_t *out, size_t out_max)
{
    size_t blocks = (n + OC_CLIP_BLOCK - 1u) / OC_CLIP_BLOCK;
    if (blocks > out_max / OC_CORE_PLAY_BYTES) return 0;
    struct CODEC2 *c2 = codec2_create(CODEC2_MODE_1200);
    if (c2 == NULL) return 0;
    /* Codec2 1200: 320 samples (40 ms) to 6 bytes, three to a payload */
    if (codec2_samples_per_frame(c2) != 320 || codec2_bytes_per_frame(c2) != 6) {
        codec2_destroy(c2);
        return 0;
    }
    short frame[320];
    size_t o = 0;
    for (size_t i = 0; i < blocks * OC_CLIP_BLOCK; i += 320u) {
        for (size_t j = 0; j < 320u; j++) frame[j] = i + j < n ? pcm[i + j] : 0;
        codec2_encode(c2, out + o, frame);
        o += 6u;
    }
    codec2_destroy(c2);
    return o;
}
