#define _GNU_SOURCE
#include "oc_conn.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

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
            if (oc_core_decode(c->rx + off, len + 2u, &m) == 0) {
                cb(ctx, &m);
                if (c->fd < 0) return -1; /* cb closed it */
            } else {
                c->bad++;
            }
            off += len + 2u;
        }
        memmove(c->rx, c->rx + off, c->rn - off);
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
        c->tn -= (size_t)w;
    }
    return 0;
}

int oc_conn_send(oc_conn_t *c, const oc_core_msg_t *m)
{
    uint8_t f[OC_CORE_FRAME_MAX];
    if (c->fd < 0) return -1;
    size_t n = oc_core_encode(m, f, sizeof(f));
    if (n == 0 || c->tn + n > sizeof(c->tx)) return -1;
    memcpy(c->tx + c->tn, f, n);
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
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    nonblock(fd);
    return fd;
}

uint32_t oc_backoff_next(uint32_t prev_ms)
{
    if (prev_ms < 1000u) return 1000u;
    return prev_ms >= 15000u ? 30000u : prev_ms * 2u;
}
