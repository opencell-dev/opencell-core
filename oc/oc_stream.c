#define _GNU_SOURCE
/* A stream channel's fetch (streaming channel spec 2026-11-01 §5): see oc_stream.h. */
#include "oc_stream.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "oc_codec.h"
#include "oc_log.h"

#if defined(__x86_64__)
#define OC_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define OC_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "oc_stream: the seccomp filter knows x86_64 and aarch64"
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

static int ll_abi(void)
{
    return (int)syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}

int oc_stream_check(const char *ffmpeg, char *why, size_t why_len)
{
    if (access(ffmpeg, X_OK) != 0) {
        snprintf(why, why_len, "stream_ffmpeg = %s: %s (apt install ffmpeg)", ffmpeg, strerror(errno));
        return -1;
    }
    if (ll_abi() < 1) {
        snprintf(why, why_len, "the kernel has no Landlock (%s): ffmpeg would run unconfined", strerror(errno));
        return -1;
    }
    return 0;
}

void oc_stream_init(oc_stream_t *s, const char *url, const char *ffmpeg)
{
    memset(s, 0, sizeof(*s));
    s->url = url;
    s->ffmpeg = ffmpeg;
    s->fd = -1;
}

int oc_stream_fd(const oc_stream_t *s) { return s->fd; }

/* ---- the child's confinement (runs between fork and exec: no heap, no stdio) ---- */

#define FS_FILE (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE)
#define FS_READ (FS_FILE | LANDLOCK_ACCESS_FS_READ_DIR)

/* The rights a ruleset of this ABI handles: all the filesystem ones it knows. */
static uint64_t ll_handled(int abi)
{
    uint64_t r = (LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1u; /* ABI 1: EXECUTE ... MAKE_SYM */
    if (abi >= 2) r |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) r |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) r |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return r;
}

/* path's tree (or file) may be used with access: a missing path is skipped. */
static void ll_allow(int rs, const char *path, uint64_t access, uint64_t handled)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) access &= FS_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;
        struct landlock_path_beneath_attr pb = { .allowed_access = access & handled, .parent_fd = fd };
        (void)syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    }
    close(fd);
}

static int ll_confine(const char *ffmpeg)
{
    int abi = ll_abi();
    if (abi < 1) return -1;
    uint64_t handled = ll_handled(abi);
    struct landlock_ruleset_attr ra;
    memset(&ra, 0, sizeof(ra));
    ra.handled_access_fs = handled;
#ifdef LANDLOCK_SCOPE_SIGNAL
    if (abi >= 6) ra.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
#endif
    int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, sizeof(ra), 0);
    if (rs < 0) return -1;
    /* What ffmpeg, its libraries, TLS and name lookup read. /etc is listed
     * file by file: /etc/opencell is not among them. */
    static const char *const ro[] = { "/usr", "/lib", "/lib64", "/bin", "/etc/ld.so.cache", "/etc/ld.so.conf",
                                      "/etc/ld.so.conf.d", "/etc/ssl", "/etc/ca-certificates", "/etc/gnutls",
                                      "/etc/crypto-policies", "/etc/resolv.conf", "/run/systemd/resolve",
                                      "/etc/nsswitch.conf", "/etc/hosts", "/etc/host.conf", "/etc/gai.conf",
                                      "/etc/localtime", "/etc/services", "/etc/protocols", "/etc/alternatives",
                                      "/etc/mime.types", "/sys/devices/system/cpu", "/proc/cpuinfo",
                                      "/dev/urandom", "/dev/random", NULL };
    for (unsigned i = 0; ro[i] != NULL; i++) ll_allow(rs, ro[i], FS_READ, handled);
    ll_allow(rs, ffmpeg, FS_FILE, handled); /* the program itself, wherever it is */
    ll_allow(rs, "/dev/null", FS_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE, handled);
    int r = (int)syscall(SYS_landlock_restrict_self, rs, 0);
    close(rs);
    return r;
}

#define DENY(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

static int sc_confine(void)
{
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, OC_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        DENY(__NR_io_uring_setup),
        DENY(__NR_ptrace),
        DENY(__NR_process_vm_readv),
        DENY(__NR_process_vm_writev),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), /* the family's low word */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES), /* AF_UNIX, AF_NETLINK, everything else */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = (unsigned short)(sizeof(f) / sizeof(f[0])), .filter = f };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

static void child(const oc_stream_t *s, int out)
{
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);
    for (int sig = 1; sig < NSIG; sig++) signal(sig, SIG_DFL);
    prctl(PR_SET_PDEATHSIG, SIGKILL); /* oc-core gone: so is its fetch */
    int nul = open("/dev/null", O_RDONLY);
    if (nul < 0 || dup2(nul, 0) < 0 || dup2(out, 1) < 0) _exit(126);
    if (syscall(SYS_close_range, 3u, ~0u, 0) != 0) {
        for (int fd = 3; fd < 4096; fd++) close(fd);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || ll_confine(s->ffmpeg) != 0 || sc_confine() != 0) _exit(125);
    char *const argv[] = { (char *)s->ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
                           "-rw_timeout", "5000000", "-user_agent", "OpenCell oc-core",
                           "-i", (char *)s->url, "-vn", "-ac", "1", "-ar", "8000",
                           "-f", "s16le", "-acodec", "pcm_s16le", "pipe:1", NULL };
    char *const envp[] = { "PATH=/usr/bin:/bin", "LC_ALL=C", NULL };
    execve(s->ffmpeg, argv, envp);
    _exit(127);
}

/* ---- the parent ---- */

static void free_enc(oc_stream_t *s)
{
    for (unsigned i = 0; i < OC_CORE_CLIPS; i++) {
        oc_clip_enc_free(s->enc[i]);
        s->enc[i] = NULL;
    }
}

/* The child's end: killed if still there, reaped; what became of it in why. */
static void reap(oc_stream_t *s, char *why, size_t why_len)
{
    int st = 0;
    pid_t r = 0;
    for (int i = 0; i < 20 && (r = waitpid(s->pid, &st, WNOHANG)) == 0; i++) { /* up to 100 ms to go by itself */
        if (i == 0) kill(s->pid, SIGTERM);
        struct timespec ts = { 0, 5000000 };
        nanosleep(&ts, NULL);
    }
    if (r == 0) {
        kill(s->pid, SIGKILL);
        r = waitpid(s->pid, &st, 0);
    }
    if (why != NULL) {
        if (r < 0) snprintf(why, why_len, "ffmpeg: waitpid: %s", strerror(errno));
        else if (WIFEXITED(st) && WEXITSTATUS(st) == 125) snprintf(why, why_len, "ffmpeg could not be confined");
        else if (WIFEXITED(st)) snprintf(why, why_len, "ffmpeg exited %d", WEXITSTATUS(st));
        else if (WIFSIGNALED(st)) snprintf(why, why_len, "ffmpeg killed by signal %d", WTERMSIG(st));
        else snprintf(why, why_len, "ffmpeg ended");
    }
    s->pid = 0;
}

static void stop(oc_stream_t *s, char *why, size_t why_len)
{
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    if (s->pid > 0) reap(s, why, why_len);
    s->epoch = 0;
    s->n = s->head = 0;
    s->has_odd = 0;
    s->ready = 0;
    s->silent = 0;
    free_enc(s);
}

void oc_stream_stop(oc_stream_t *s) { stop(s, NULL, 0); }

static int start(oc_stream_t *s, uint32_t epoch, uint64_t now_us)
{
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0) child(s, p[1]); /* never returns */
    close(p[1]);
    int fl = fcntl(p[0], F_GETFL);
    fcntl(p[0], F_SETFL, fl | O_NONBLOCK);
    s->fd = p[0];
    s->pid = pid;
    s->epoch = epoch;
    s->opened_us = now_us;
    return 0;
}

void oc_stream_sync(oc_stream_t *s, unsigned ch, oc_core_t *k, uint64_t now_us)
{
    uint32_t want = oc_core_stream_wanted(k, ch);
    if (want == s->epoch) return;
    if (s->epoch != 0) {
        char why[96];
        stop(s, why, sizeof(why));
        oc_log(OC_LOG_INFO, "stream %u: fetch stopped (%s)", ch, why);
    }
    if (want == 0) return;
    if (start(s, want, now_us) != 0) {
        oc_log(OC_LOG_ERR, "stream %u: can't start %s: %s", ch, s->ffmpeg, strerror(errno));
        oc_core_stream_failed(k, ch, want, "can't start ffmpeg", now_us);
        return;
    }
    oc_log(OC_LOG_INFO, "stream %u: fetching %s (ffmpeg pid %d)", ch, s->url, (int)s->pid);
}

/* n samples onto the ring's end, the oldest dropped past OC_STREAM_KEEP_SAMPLES. */
static void put(oc_stream_t *s, const int16_t *x, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s->n == OC_STREAM_KEEP_SAMPLES) {
            s->head = (s->head + 1u) % OC_STREAM_KEEP_SAMPLES;
            s->n--;
        }
        s->buf[(s->head + s->n) % OC_STREAM_KEEP_SAMPLES] = x[i];
        s->n++;
    }
}

void oc_stream_read(oc_stream_t *s, unsigned ch, oc_core_t *k, uint64_t now_us)
{
    uint8_t b[16384 + 1];
    int16_t x[sizeof(b) / 2];
    for (int turns = 0; turns < 8 && s->fd >= 0; turns++) { /* at most 128 KB a turn: the loop goes on */
        size_t off = 0;
        if (s->has_odd) b[off++] = s->odd;
        ssize_t r = read(s->fd, b + off, sizeof(b) - 1u - off);
        if (r < 0 && (errno == EAGAIN || errno == EINTR)) break;
        if (r <= 0) {
            char why[96];
            uint32_t epoch = s->epoch;
            if (r < 0) snprintf(why, sizeof(why), "read: %s", strerror(errno));
            stop(s, r < 0 ? NULL : why, sizeof(why));
            oc_log(OC_LOG_WARNING, "stream %u: fetch ended: %s", ch, why);
            oc_core_stream_failed(k, ch, epoch, why, now_us);
            return;
        }
        size_t len = off + (size_t)r, n = len / 2u;
        s->has_odd = (uint8_t)(len & 1u);
        if (s->has_odd) s->odd = b[len - 1u];
        for (size_t i = 0; i < n; i++) x[i] = (int16_t)(b[2 * i] | b[2 * i + 1] << 8); /* s16le */
        put(s, x, n);
    }
    if (!s->ready && s->n >= OC_STREAM_READY_SAMPLES) {
        s->ready = 1;
        oc_log(OC_LOG_INFO, "stream %u: first audio after %u ms", ch, (unsigned)((now_us - s->opened_us) / 1000u));
        oc_core_stream_ready(k, ch, s->epoch, now_us);
    }
}

int oc_stream_pull(oc_stream_t *s, const oc_core_stream_cfg_t *sc, uint32_t skip, uint8_t want,
                   uint8_t out[OC_CORE_CLIPS][OC_CORE_PLAY_BYTES])
{
    int16_t blk[OC_CLIP_BLOCK];
    size_t drop = (size_t)skip * OC_CLIP_BLOCK;
    if (drop > s->n) drop = s->n;
    s->head = (s->head + drop) % OC_STREAM_KEEP_SAMPLES;
    s->n -= drop;
    if (s->n >= OC_CLIP_BLOCK) {
        for (size_t i = 0; i < OC_CLIP_BLOCK; i++) blk[i] = s->buf[(s->head + i) % OC_STREAM_KEEP_SAMPLES];
        s->head = (s->head + OC_CLIP_BLOCK) % OC_STREAM_KEEP_SAMPLES;
        s->n -= OC_CLIP_BLOCK;
        s->silent = 0;
    } else { /* a short stall: silence, never a gap in the pacing (spec §4.5) */
        memset(blk, 0, sizeof(blk));
        if (++s->silent >= OC_STREAM_SILENT_BLOCKS) return -1;
    }
    for (unsigned i = 0; i < sc->noffline && i < OC_CORE_CLIPS; i++) {
        if (!(want & 1u << i)) continue;
        if (s->enc[i] == NULL && (s->enc[i] = oc_clip_enc_new(sc->offline[i].codec)) == NULL) return -1;
        oc_clip_enc_block(s->enc[i], blk, out[i]);
    }
    return 0;
}
