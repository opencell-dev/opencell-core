/* The playback clip (playback clip spec 2026-10-12 §4; OpenVoxNB spec V7): the WAV reader and the encoders. */
#include "oc_clip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec2.h"
#include "oc_codec.h"
#include "oc_core.h"
#include "oc_vox.h"

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
    if (fmt == NULL) {
        snprintf(why, why_len, "no fmt chunk");
        return -1;
    }
    if (fmt_len < 16) {
        snprintf(why, why_len, "a fmt chunk of %u bytes (at least 16)", (unsigned)fmt_len);
        return -1;
    }
    if (data == NULL) {
        snprintf(why, why_len, "no data chunk");
        return -1;
    }
    unsigned format = le16(fmt), ch = le16(fmt + 2), bits = le16(fmt + 14);
    uint32_t rate = le32(fmt + 4);
    if (format != 1 || ch != 1 || rate != OC_CLIP_RATE || bits != 16) {
        snprintf(why, why_len, "%u Hz, %u channel%s, %u-bit, format %u; it must be 8000 Hz mono 16-bit PCM (format 1)",
                 (unsigned)rate, ch, ch == 1 ? "" : "s", bits, format);
        return -1;
    }
    if (le16(fmt + 12) != 2) {
        snprintf(why, why_len, "block align %u; it must be 2 for mono 16-bit PCM", le16(fmt + 12));
        return -1;
    }
    if (data_len & 1u) {
        snprintf(why, why_len, "a data chunk of an odd length");
        return -1;
    }
    size_t samples = data_len / 2u;
    if (samples < OC_CLIP_MIN_SAMPLES || samples > OC_CLIP_MAX_SAMPLES) {
        /* hundredths of a second: rounded down when short, up when long, so a
         * refusal never prints exactly the limit */
        size_t cs = samples > OC_CLIP_MAX_SAMPLES ? (samples + 79u) / 80u : samples / 80u;
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

_Static_assert(OC_CLIP_BLOCK == OC_VOX_BLOCK_SAMPLES, "an OpenVoxNB block is the 120 ms clip block");

const uint8_t oc_clip_codecs[OC_CLIP_CODECS] = { OC_CODEC_C2_1200, OC_CODEC_OVX_1200, OC_CODEC_OVX_1000,
                                                 OC_CODEC_OVX_800, OC_CODEC_OVX_600 };

/* OpenVoxNB: 960 samples to one block of the mode's size, as `oc-vox enc`. */
static size_t encode_ovx(oc_vox_mode_t mode, const int16_t *pcm, size_t n, uint8_t *out, size_t out_max)
{
    oc_vox_enc_t e;
    int16_t block[OC_VOX_BLOCK_SAMPLES];
    size_t blocks = (n + OC_CLIP_BLOCK - 1u) / OC_CLIP_BLOCK, bytes = oc_vox_block_bytes(mode);
    if (bytes == 0 || blocks > out_max / bytes || oc_vox_enc_init(&e, mode) != 0) return 0;
    for (size_t b = 0; b < blocks; b++) {
        for (size_t j = 0; j < OC_CLIP_BLOCK; j++) {
            size_t i = b * OC_CLIP_BLOCK + j;
            block[j] = i < n ? pcm[i] : 0;
        }
        oc_vox_encode(&e, block, out + b * bytes);
    }
    return blocks * bytes;
}

size_t oc_clip_encode(uint8_t codec, const int16_t *pcm, size_t n, uint8_t *out, size_t out_max)
{
    if (codec == OC_CODEC_C2_1200) return oc_clip_encode_c2_1200(pcm, n, out, out_max);
    int mode = oc_vox_mode_of_codec_id(codec);
    return mode == OC_VOX_MODE_NONE ? 0 : encode_ovx((oc_vox_mode_t)mode, pcm, n, out, out_max);
}

struct oc_clip_enc {
    uint8_t        codec;
    size_t         bytes; /* one block's */
    struct CODEC2 *c2;  /* Codec2 1200 */
    oc_vox_enc_t   vox; /* else */
};

oc_clip_enc_t *oc_clip_enc_new(uint8_t codec)
{
    oc_clip_enc_t *e = calloc(1, sizeof(*e));
    if (e == NULL) return NULL;
    e->codec = codec;
    if (codec == OC_CODEC_C2_1200) {
        e->c2 = codec2_create(CODEC2_MODE_1200);
        e->bytes = OC_CORE_PLAY_BYTES;
        if (e->c2 != NULL && codec2_samples_per_frame(e->c2) == 320 && codec2_bytes_per_frame(e->c2) == 6) return e;
        if (e->c2 != NULL) codec2_destroy(e->c2);
    } else {
        int mode = oc_vox_mode_of_codec_id(codec);
        if (mode != OC_VOX_MODE_NONE) e->bytes = oc_vox_block_bytes((oc_vox_mode_t)mode);
        if (mode != OC_VOX_MODE_NONE && e->bytes != 0 && e->bytes <= OC_CORE_PLAY_BYTES &&
            oc_vox_enc_init(&e->vox, (oc_vox_mode_t)mode) == 0) {
            return e;
        }
    }
    free(e);
    return NULL;
}

size_t oc_clip_enc_block(oc_clip_enc_t *e, const int16_t pcm[OC_CLIP_BLOCK], uint8_t *out)
{
    if (e->c2 != NULL) {
        short frame[320];
        for (size_t i = 0; i < OC_CLIP_BLOCK; i += 320u) {
            for (size_t j = 0; j < 320u; j++) frame[j] = pcm[i + j];
            codec2_encode(e->c2, out + i / 320u * 6u, frame);
        }
        return OC_CORE_PLAY_BYTES;
    }
    oc_vox_encode(&e->vox, pcm, out);
    return e->bytes;
}

void oc_clip_enc_free(oc_clip_enc_t *e)
{
    if (e == NULL) return;
    if (e->c2 != NULL) codec2_destroy(e->c2);
    free(e);
}
