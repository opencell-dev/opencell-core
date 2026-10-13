/* The playback clip (playback clip spec 2026-10-12 §4): the WAV reader and
 * the Codec2 1200 encoder. */
#include "oc_clip.h"

#include <stdlib.h>
#include <string.h>

#include "codec2.h"
#include "oc_core.h"

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
