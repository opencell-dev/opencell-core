/* The playback clip (playback clip spec 2026-10-12): an 8 kHz mono 16-bit
 * WAV file, read and encoded by oc-core at start. */
#ifndef OC_CLIP_H
#define OC_CLIP_H

#include <stddef.h>
#include <stdint.h>

#define OC_CLIP_RATE        8000u
#define OC_CLIP_MIN_SAMPLES 8000u           /* 1 s */
#define OC_CLIP_MAX_SAMPLES 4800000u        /* 10 min */
#define OC_CLIP_BLOCK       960u            /* 120 ms: one OC_CORE_PLAY_BYTES payload */

/* The samples of a WAV file held whole in buf (spec §4.1): RIFF/WAVE, PCM
 * format 1, mono, 8000 Hz, 16-bit, OC_CLIP_MIN_SAMPLES to
 * OC_CLIP_MAX_SAMPLES. 0 with *pcm malloc'd (the caller frees it) and *n
 * its sample count; or -1 with the reason in why (NUL-terminated). */
int oc_wav_read(const uint8_t *buf, size_t len, int16_t **pcm, size_t *n, char *why, size_t why_len);

/* n samples of pcm encoded with Codec2 1200, padded with silence to whole
 * OC_CLIP_BLOCKs: one OC_CORE_PLAY_BYTES payload per block, in order, one
 * encoder for the whole clip. The bytes written, or 0 if out_max is too
 * small or the encoder can't be made. */
size_t oc_clip_encode_c2_1200(const int16_t *pcm, size_t n, uint8_t *out, size_t out_max);

#endif
