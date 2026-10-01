#define _GNU_SOURCE
#include "oc_conn.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "oc_sig_keys.h" /* oc_sig_wipe */

static void nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

void oc_conn_init(oc_conn_t *c, int fd)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    if (fd >= 0) nonblock(fd);
}

void oc_conn_close(oc_conn_t *c)
{
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    oc_sig_wipe(c->rx, sizeof(c->rx)); /* what was read or queued is gone with the link, key material too */
    oc_sig_wipe(c->tx, sizeof(c->tx));
    c->rn = c->tn = 0;
}

int oc_conn_read(oc_conn_t *c, oc_conn_rx_fn cb, void *ctx)
{
    if (c->fd < 0) return -1;
    for (;;) {
        ssize_t r = recv(c->fd, c->rx + c->rn, sizeof(c->rx) - c->rn, 0);
        if (r == 0) return -1; /* the peer closed */
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            return -1;
        }
        c->rn += (size_t)r;
        size_t off = 0;
        while (c->rn - off >= 2) {
            size_t len = ((size_t)c->rx[off] << 8) | c->rx[off + 1];
            if (len == 0 || len + 2u > OC_CORE_FRAME_MAX) return -1; /* the stream is broken */
            if (c->rn - off < len + 2u) break;
            oc_core_msg_t m;
            int ok = oc_core_decode(c->rx + off, len + 2u, &m) == 0;
            if (ok) cb(ctx, &m);
            oc_sig_wipe(&m, sizeof(m)); /* an AV_RES's CK and IK (oc-cell's side) */
            if (!ok) c->bad++;
            else if (c->fd < 0) return -1; /* cb closed it */
            off += len + 2u;
        }
        memmove(c->rx, c->rx + off, c->rn - off);
        oc_sig_wipe(c->rx + c->rn - off, off); /* the frames handed on */
        c->rn -= off;
    }
}

int oc_conn_flush(oc_conn_t *c)
{
    if (c->fd < 0) return -1;
    while (c->tn > 0) {
        ssize_t w = send(c->fd, c->tx, c->tn, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            return -1;
        }
        memmove(c->tx, c->tx + w, c->tn - (size_t)w);
        oc_sig_wipe(c->tx + c->tn - (size_t)w, (size_t)w); /* the bytes sent (an AV_RES's CK and IK, say) */
        c->tn -= (size_t)w;
    }
    return 0;
}

int oc_conn_send(oc_conn_t *c, const oc_core_msg_t *m)
{
    uint8_t f[OC_CORE_FRAME_MAX];
    if (c->fd < 0) return -1;
    size_t n = oc_core_encode(m, f, sizeof(f));
    if (n == 0 || c->tn + n > sizeof(c->tx)) {
        oc_sig_wipe(f, sizeof(f));
        return -1;
    }
    memcpy(c->tx + c->tn, f, n);
    oc_sig_wipe(f, sizeof(f));
    c->tn += n;
    return oc_conn_flush(c);
}

static int unix_addr(const char *path, struct sockaddr_un *a)
{
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(a->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(a->sun_path, path);
    return 0;
}

int oc_unix_listen(const char *path, unsigned mode, const char *group)
{
    struct sockaddr_un a;
    struct stat st;
    int e;
    if (unix_addr(path, &a) != 0) return -1;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            errno = EEXIST; /* not ours to remove */
            return -1;
        }
        unlink(path);
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    mode_t old = umask(0177); /* never reachable by others, even for a moment */
    int r = bind(fd, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (r != 0 || chmod(path, (mode_t)mode) != 0) goto fail;
    if (group != NULL) {
        struct group *g = getgrnam(group);
        if (g == NULL) {
            errno = ENOENT;
            goto fail;
        }
        if (chown(path, (uid_t)-1, g->gr_gid) != 0) goto fail;
    }
    if (listen(fd, 16) != 0) goto fail;
    nonblock(fd);
    return fd;
fail:
    e = errno;
    close(fd);
    unlink(path);
    errno = e;
    return -1;
}

int oc_unix_connect(const char *path)
{
    struct sockaddr_un a;
    if (unix_addr(path, &a) != 0) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0 && errno != EINPROGRESS) {
        int e = errno; /* EAGAIN: the backlog is full - never wait for it here */
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

static long left_ms(const struct timespec *end)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (end->tv_sec - t.tv_sec) * 1000L + (end->tv_nsec - t.tv_nsec) / 1000000L;
}

int oc_unix_connect_wait(const char *path, int timeout_ms)
{
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += timeout_ms / 1000;
    end.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (end.tv_nsec >= 1000000000L) {
        end.tv_sec++;
        end.tv_nsec -= 1000000000L;
    }
    for (;;) {
        int fd = oc_unix_connect(path);
        if (fd < 0 && errno != EAGAIN) return -1;
        long left = left_ms(&end);
        if (fd >= 0) {
            struct pollfd p = { fd, POLLOUT, 0 };
            int err = 0;
            socklen_t len = sizeof(err);
            int r = poll(&p, 1, left > 0 ? (int)left : 0);
            if (r == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) return fd;
            close(fd);
            if (r == 1 && err != 0 && err != EAGAIN) {
                errno = err;
                return -1;
            }
            if (r < 0 && errno != EINTR) return -1;
        }
        if (left <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct timespec d = { 0, (left < 20 ? left : 20) * 1000000L }; /* room in the backlog soon? */
        nanosleep(&d, NULL);
    }
}

uint32_t oc_backoff_next(uint32_t prev_ms)
{
    if (prev_ms < 1000u) return 1000u;
    return prev_ms >= 15000u ? 30000u : prev_ms * 2u;
}
