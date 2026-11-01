/* A stream channel's fetch (streaming channel spec 2026-11-01 §5): ffmpeg as
 * a confined child turning the station's URL into 8 kHz mono 16-bit PCM on
 * a pipe, read without blocking in oc-core's poll loop, buffered, and
 * encoded block by block for oc_core (io.stream_pull).
 *
 * The child can't reach the core's secrets (§5.2): between fork and exec it
 * keeps only its stdout pipe and stderr, takes a Landlock ruleset that lets
 * it read and run only system files (no /etc/opencell, no /var/lib/opencell,
 * no credentials) and write only /dev/null, scoped so it can signal nothing
 * outside itself, and a seccomp filter that refuses it AF_UNIX and
 * AF_NETLINK sockets, io_uring, ptrace and process_vm_*. */
#ifndef OC_STREAM_H
#define OC_STREAM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "oc_clip.h"
#include "oc_core.h"

#define OC_STREAM_READY_SAMPLES 8000u  /* 1 s buffered: the channel plays */
#define OC_STREAM_KEEP_SAMPLES  24000u /* at most 3 s kept (oldest dropped): listeners stay near live */
#define OC_STREAM_SILENT_BLOCKS 42u    /* 42 blocks (5.04 s) pulled with no audio: failed */

typedef struct {
    const char    *url;
    const char    *ffmpeg;
    uint32_t       epoch;  /* the opening this fetch serves; 0: none */
    pid_t          pid;    /* 0: no child */
    int            fd;     /* its stdout; -1: none */
    int16_t        buf[OC_STREAM_KEEP_SAMPLES];
    size_t         head, n; /* ring: n samples from head */
    uint8_t        odd, has_odd; /* a sample's first byte, read alone */
    int            ready;   /* oc_core_stream_ready was called for this epoch */
    unsigned       silent;  /* consecutive blocks pulled without audio */
    uint64_t       opened_us;
    oc_clip_enc_t *enc[OC_CORE_CLIPS]; /* per offline copy index, made when first wanted */
} oc_stream_t;

/* 0 if channels can be fetched: ffmpeg is executable and the kernel has
 * Landlock (no confinement, no fetch: §5.2); else -1 with why. */
int  oc_stream_check(const char *ffmpeg, char *why, size_t why_len);
void oc_stream_init(oc_stream_t *s, const char *url, const char *ffmpeg);
/* After each oc_core call that can change it: start, restart or stop the
 * child for the epoch oc_core wants (oc_core_stream_wanted). */
void oc_stream_sync(oc_stream_t *s, unsigned ch, oc_core_t *k, uint64_t now_us);
/* The fd to poll for POLLIN, or -1. */
int  oc_stream_fd(const oc_stream_t *s);
/* The fd was readable or hung up: PCM is taken in; ready or failed are
 * reported to oc_core. */
void oc_stream_read(oc_stream_t *s, unsigned ch, oc_core_t *k, uint64_t now_us);
/* io.stream_pull's work for this channel (oc_core.h); sc: its config. */
int  oc_stream_pull(oc_stream_t *s, const oc_core_stream_cfg_t *sc, uint32_t skip, uint8_t want,
                    uint8_t out[OC_CORE_CLIPS][OC_CORE_PLAY_BYTES]);
/* Kill and reap any child (oc-core is stopping). */
void oc_stream_stop(oc_stream_t *s);

#endif
