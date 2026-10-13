#define _GNU_SOURCE
#include "oc_cellsrv.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "oc_addr.h"
#include "oc_log.h"

void oc_cellsrv_log_tick(oc_cellsrv_throttle_t *t, uint64_t now_us)
{
    if (t->n == 0 || now_us - t->start_us < (uint64_t)OC_CELLSRV_LOG_S * 1000000u) return;
    if (t->n > OC_CELLSRV_LOG_N) {
        oc_log(OC_LOG_WARNING, "cell TLS: %u more refusals in the last %u s (not logged one by one)",
               t->n - OC_CELLSRV_LOG_N, OC_CELLSRV_LOG_S);
    }
    t->n = 0;
}

int oc_cellsrv_log_ok(oc_cellsrv_throttle_t *t, uint64_t now_us)
{
    oc_cellsrv_log_tick(t, now_us);
    if (t->n == 0) t->start_us = now_us;
    if (t->n < UINT_MAX) t->n++;
    return t->n <= OC_CELLSRV_LOG_N;
}

int oc_cellsrv_open(oc_cellsrv_t *s, const char *text, oc_tls_t *tls, uint64_t (*now_us)(void), char *err, size_t cap)
{
    struct sockaddr_storage sa;
    socklen_t len;
    memset(s, 0, sizeof(*s));
    s->lfd = -1;
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) s->hs[i].tls.fd = -1;
    if (oc_addr_parse(text, &sa, &len, NULL) != 0) {
        snprintf(err, cap, "cell_listen = '%s': ADDRESS:PORT, e.g. 0.0.0.0:7443 or [::]:7443", text);
        return -1;
    }
    int fd = socket(sa.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), one = 1;
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) != 0 ||
        bind(fd, (struct sockaddr *)&sa, len) != 0 || listen(fd, 16) != 0) {
        snprintf(err, cap, "cell_listen = '%s': %s", text, strerror(errno));
        if (fd >= 0) close(fd);
        return -1;
    }
    s->lfd = fd;
    s->tls = tls;
    s->now_us = now_us;
    return 0;
}

uint16_t oc_cellsrv_port(const oc_cellsrv_t *s)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    if (s->lfd < 0 || getsockname(s->lfd, (struct sockaddr *)&sa, &len) != 0) return 0;
    return ntohs(sa.ss_family == AF_INET ? ((struct sockaddr_in *)&sa)->sin_port
                                         : ((struct sockaddr_in6 *)&sa)->sin6_port);
}

static void peer_text(const struct sockaddr_storage *sa, char *out, size_t cap)
{
    char host[INET6_ADDRSTRLEN] = "?";
    if (sa->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, host, sizeof(host));
        snprintf(out, cap, "%s:%u", host, ntohs(((const struct sockaddr_in *)sa)->sin_port));
    } else {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, host, sizeof(host));
        snprintf(out, cap, "[%s]:%u", host, ntohs(((const struct sockaddr_in6 *)sa)->sin6_port));
    }
}

static void accept_one(oc_cellsrv_t *s)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int fd = accept4(s->lfd, (struct sockaddr *)&sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;
    char addr[64];
    peer_text(&sa, addr, sizeof(addr));
    oc_cellsrv_hs_t *h = NULL;
    for (unsigned i = 0; i < OC_CELLSRV_PENDING && h == NULL; i++) {
        if (!s->hs[i].used) h = &s->hs[i];
    }
    if (h == NULL) {
        uint64_t now = s->now_us();
        if (s->full_logged_us == 0 || now - s->full_logged_us >= 10000000u) {
            oc_log(OC_LOG_WARNING, "cell TLS: %s: refused, %u handshakes in progress already", addr, OC_CELLSRV_PENDING);
            s->full_logged_us = now;
        }
        close(fd);
        return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    memset(h, 0, sizeof(*h));
    if (oc_tls_conn_start(s->tls, &h->tls, fd) != 0) {
        oc_log(OC_LOG_ERR, "cell TLS: %s: no TLS session (out of memory?)", addr);
        h->tls.fd = -1;
        return;
    }
    h->used = 1;
    h->since_us = s->now_us();
    snprintf(h->addr, sizeof(h->addr), "%s", addr);
}

unsigned oc_cellsrv_fds(oc_cellsrv_t *s, struct pollfd *p)
{
    unsigned n = 0;
    if (s->lfd < 0) return 0;
    p[n] = (struct pollfd){ s->lfd, POLLIN, 0 };
    s->at[n++] = -1;
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) {
        if (!s->hs[i].used) continue;
        p[n] = (struct pollfd){ s->hs[i].tls.fd, s->hs[i].tls.want, 0 };
        s->at[n++] = (int)i;
    }
    return n;
}

static void hs_close(oc_cellsrv_t *s, oc_cellsrv_hs_t *h, int prio, const char *why)
{
    if (why != NULL && oc_cellsrv_log_ok(&s->fail, s->now_us())) oc_log(prio, "cell TLS: %s: closed: %s", h->addr, why);
    oc_tls_conn_close(&h->tls);
    h->used = 0;
}

void oc_cellsrv_serve(oc_cellsrv_t *s, const struct pollfd *p, unsigned n, oc_cellsrv_ready_fn ready, void *ctx)
{
    for (unsigned k = 0; k < n; k++) {
        if (s->at[k] < 0) {
            if (p[k].revents & POLLIN) accept_one(s);
            continue;
        }
        oc_cellsrv_hs_t *h = &s->hs[s->at[k]];
        if (!h->used || p[k].revents == 0) continue;
        int r = oc_tls_conn_handshake(&h->tls);
        if (r < 0) {
            hs_close(s, h, OC_LOG_WARNING, h->tls.why[0] != '\0' ? h->tls.why : "handshake failed");
        } else if (r == 1) {
            char addr[64];
            snprintf(addr, sizeof(addr), "%s", h->addr);
            h->used = 0;
            ready(ctx, &h->tls, addr); /* the daemon moves it out, or closes it */
            if (h->tls.ssl != NULL || h->tls.fd >= 0) oc_tls_conn_close(&h->tls);
        }
    }
    uint64_t now = s->now_us();
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) {
        oc_cellsrv_hs_t *h = &s->hs[i];
        if (h->used && now - h->since_us >= (uint64_t)OC_CELLSRV_HANDSHAKE_S * 1000000u) {
            hs_close(s, h, OC_LOG_WARNING, "no handshake in 10 s");
        }
    }
    oc_cellsrv_log_tick(&s->fail, now);
}

void oc_cellsrv_close(oc_cellsrv_t *s)
{
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) {
        if (s->hs[i].used) hs_close(s, &s->hs[i], 0, NULL);
    }
    if (s->lfd >= 0) close(s->lfd);
    s->lfd = -1;
}
