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

static void nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static long fd_recv(void *ctx, void *buf, size_t n)
{
    oc_conn_t *c = ctx;
    for (;;) {
        ssize_t r = recv(c->fd, buf, n, 0);
        if (r > 0) return (long)r;
        if (r == 0) return -1; /* the peer closed */
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno != EINTR) return -1;
    }
}

static long fd_send(void *ctx, const void *buf, size_t n)
{
    oc_conn_t *c = ctx;
    for (;;) {
        ssize_t w = send(c->fd, buf, n, MSG_NOSIGNAL);
        if (w >= 0) return (long)w;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno != EINTR) return -1;
    }
}

static void fd_close(void *ctx) { close(((oc_conn_t *)ctx)->fd); }

void oc_conn_init(oc_conn_t *c, int fd)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->io = (oc_conn_io_t){ c, fd_recv, fd_send, fd_close };
    if (fd >= 0) nonblock(fd);
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
