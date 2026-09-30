#define _GNU_SOURCE
/* A slow admin peer for the process tests: connects to an admin socket and
 * sends "status\0" one byte every INTERVAL_MS, never shutting its side, then
 * holds the connection until the daemon closes it (or HOLD_S pass).
 *
 *   tool_oc_drip SOCKET INTERVAL_MS HOLD_S
 *
 * Prints "closed after N ms" when the daemon drops it. */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "oc_conn.h"

static long ms_since(const struct timespec *t0)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000L + (t.tv_nsec - t0->tv_nsec) / 1000000L;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: tool_oc_drip SOCKET INTERVAL_MS HOLD_S\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    int fd = oc_unix_connect(argv[1]);
    if (fd < 0) {
        perror(argv[1]);
        return 1;
    }
    static const char req[] = "status"; /* with its NUL: 7 bytes */
    int interval = atoi(argv[2]);
    long hold_ms = atol(argv[3]) * 1000L;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    size_t sent = 0;
    while (ms_since(&t0) < hold_ms) {
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, interval) > 0) {
            char b[256];
            ssize_t r = recv(fd, b, sizeof(b), 0);
            if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
                printf("closed after %ld ms\n", ms_since(&t0));
                close(fd);
                return 0;
            }
            continue;
        }
        if (sent < sizeof(req)) {
            if (send(fd, req + sent, 1, MSG_NOSIGNAL) == 1) sent++;
        }
    }
    printf("held %ld ms\n", ms_since(&t0));
    close(fd);
    return 1;
}
