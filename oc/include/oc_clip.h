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

/* The codecs oc-core encodes the clip with, in the order admin status
 * lists them (OpenVoxNB spec V7). */
#define OC_CLIP_CODECS 5u
extern const uint8_t oc_clip_codecs[OC_CLIP_CODECS];

/* n samples of pcm encoded with codec (oc_codec.h: Codec2 1200, or
 * OVX-600 ... OVX-1200 with oc_vox's fixed-point encoder), padded with
 * silence to whole OC_CLIP_BLOCKs: one block of oc_codec_block_bytes(codec)
 * per 960 samples, in order, one encoder for the whole clip - the bytes
 * c2enc or `oc-vox enc` gives. The bytes written, or 0: a codec with no
 * encoder here, out_max too small, or an encoder that can't be made. */
size_t oc_clip_encode(uint8_t codec, const int16_t *pcm, size_t n, uint8_t *out, size_t out_max);

/* One live encoder (streaming channel spec §5.2): blocks of OC_CLIP_BLOCK
 * samples in, one after another, each to one block of codec - the bytes
 * oc_clip_encode gives for the same samples. new: NULL for a codec with no
 * encoder here (or out of memory). block: the bytes written to out (at
 * most OC_CORE_PLAY_BYTES). */
typedef struct oc_clip_enc oc_clip_enc_t;
oc_clip_enc_t *oc_clip_enc_new(uint8_t codec);
size_t         oc_clip_enc_block(oc_clip_enc_t *e, const int16_t pcm[OC_CLIP_BLOCK], uint8_t *out);
void           oc_clip_enc_free(oc_clip_enc_t *e);

#endif
