#define _GNU_SOURCE
/* Odd admin peers for the process tests.
 *
 *   tool_oc_drip SOCKET INTERVAL_MS HOLD_S
 *       Sends "status\0" one byte every INTERVAL_MS, never shutting its
 *       side, and holds the connection until the daemon closes it (or HOLD_S
 *       pass). Prints "closed after N ms" when the daemon drops it.
 *   tool_oc_drip --flood SOCKET N WORD
 *       N requests of one word each, one connection each, every answer read
 *       in full (each leaves an audit record). Prints "flooded N".
 *   tool_oc_drip --late-read SOCKET PAUSE_S WORD...
 *       Sends a request at once, reads nothing for PAUSE_S, then reads the
 *       answer. Prints "rc RC" and "expected E got G" (RC and E from the
 *       answer's head "RC BYTES\n", G the bytes after it), and "cut" if
 *       G < E.
 *   tool_oc_drip --hang-up SOCKET WORD...
 *       Sends a request and closes at once, taking no answer.
 *   tool_oc_drip --serve SOCKET ANSWER...
 *       A stand-in daemon: takes one connection per ANSWER, reads its
 *       request to the end, prints "request: WORDS" (its NULs as spaces),
 *       answers ANSWER as it is, and closes. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static void blocking(int fd)
{
    struct timeval tv = { 10, 0 };
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK); /* oc_unix_connect's is non-blocking */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int connect_blocking(const char *path)
{
    int fd = oc_unix_connect_wait(path, 10000);
    if (fd < 0) {
        perror(path);
        exit(1);
    }
    blocking(fd);
    return fd;
}

static int drip(int argc, char **argv)
{
    if (argc != 4) return 2;
    int fd = oc_unix_connect_wait(argv[1], 10000);
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

static int flood(int argc, char **argv)
{
    if (argc != 5) return 2;
    long n = atol(argv[3]);
    for (long i = 0; i < n; i++) {
        int fd = connect_blocking(argv[2]);
        if (send(fd, argv[4], strlen(argv[4]) + 1u, MSG_NOSIGNAL) < 0) return 1;
        shutdown(fd, SHUT_WR);
        char b[4096];
        ssize_t r;
        while ((r = recv(fd, b, sizeof(b), 0)) > 0) {
        }
        close(fd);
        if (r < 0) return 1;
    }
    printf("flooded %ld\n", n);
    return 0;
}

static int late_read(int argc, char **argv)
{
    if (argc < 5) return 2;
    int fd = connect_blocking(argv[2]);
    for (int i = 4; i < argc; i++) {
        if (send(fd, argv[i], strlen(argv[i]) + 1u, MSG_NOSIGNAL) < 0) return 1;
    }
    shutdown(fd, SHUT_WR);
    sleep((unsigned)atoi(argv[3])); /* reads nothing meanwhile */
    char b[65536], head[32];
    size_t hn = 0, got = 0;
    unsigned long long expected = 0;
    int in_head = 1;
    ssize_t r;
    while ((r = recv(fd, b, sizeof(b), 0)) > 0) {
        for (ssize_t i = 0; i < r; i++) {
            if (!in_head) {
                got++;
            } else if (b[i] == '\n' || hn == sizeof(head) - 1u) {
                head[hn] = '\0';
                in_head = 0;
                const char *sp = strchr(head, ' ');
                expected = sp != NULL ? strtoull(sp + 1, NULL, 10) : 0;
            } else {
                head[hn++] = b[i];
            }
        }
    }
    close(fd);
    printf("rc %.*s\n", (int)strcspn(head, " "), head);
    printf("expected %llu got %zu\n", expected, got);
    if (got < expected) printf("cut\n");
    return 0;
}

static int hang_up(int argc, char **argv)
{
    if (argc < 4) return 2;
    int fd = connect_blocking(argv[2]);
    for (int i = 3; i < argc; i++) {
        if (send(fd, argv[i], strlen(argv[i]) + 1u, MSG_NOSIGNAL) < 0) return 1;
    }
    shutdown(fd, SHUT_WR);
    close(fd);
    return 0;
}

static int serve(int argc, char **argv)
{
    if (argc < 4) return 2;
    int l = oc_unix_listen(argv[2], 0600, NULL);
    if (l < 0) {
        perror(argv[2]);
        return 1;
    }
    int rc = 0;
    for (int i = 3; i < argc && rc == 0; i++) {
        struct pollfd p = { l, POLLIN, 0 };
        int fd = poll(&p, 1, 10000) > 0 ? accept(l, NULL, NULL) : -1;
        if (fd < 0) {
            rc = 1;
            break;
        }
        blocking(fd);
        char b[4096];
        size_t n = 0;
        ssize_t r;
        while ((r = recv(fd, b + n, sizeof(b) - 1u - n, 0)) > 0) {
            n += (size_t)r;
            if (n == sizeof(b) - 1u) n = 0; /* only a short request is shown */
        }
        for (size_t j = 0; j + 1u < n; j++) {
            if (b[j] == '\0') b[j] = ' ';
        }
        b[n] = '\0';
        printf("request: %s\n", b);
        fflush(stdout);
        send(fd, argv[i], strlen(argv[i]), MSG_NOSIGNAL);
        close(fd);
    }
    close(l);
    unlink(argv[2]);
    return rc;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    int rc = 2;
    if (argc > 1 && strcmp(argv[1], "--flood") == 0) rc = flood(argc, argv);
    else if (argc > 1 && strcmp(argv[1], "--late-read") == 0) rc = late_read(argc, argv);
    else if (argc > 1 && strcmp(argv[1], "--hang-up") == 0) rc = hang_up(argc, argv);
    else if (argc > 1 && strcmp(argv[1], "--serve") == 0) rc = serve(argc, argv);
    else if (argc > 1 && strncmp(argv[1], "--", 2) != 0) rc = drip(argc, argv);
    if (rc == 2) {
        fprintf(stderr, "usage: tool_oc_drip SOCKET INTERVAL_MS HOLD_S | --flood SOCKET N WORD\n"
                        "     | --late-read SOCKET PAUSE_S WORD... | --hang-up SOCKET WORD...\n"
                        "     | --serve SOCKET ANSWER...\n");
    }
    return rc;
}
