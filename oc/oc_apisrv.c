#define _GNU_SOURCE
#include "oc_apisrv.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oc_log.h"
#include "oc_sig_keys.h" /* oc_sig_wipe */

enum { C_FREE = 0, C_HANDSHAKE, C_OPEN };
enum { P_HANDSHAKE, P_IDLE, P_FRAME, P_ANSWER };

static const unsigned LIMIT_S[] = { OC_APISRV_HANDSHAKE_S, OC_APISRV_IDLE_S, OC_APISRV_FRAME_S, OC_APISRV_ANSWER_S };
static const char *const PHASE[] = { "the handshake", "idle", "a request", "an answer" };

static int private4(uint32_t a) /* host order */
{
    return (a >> 24) == 10 || (a >> 20) == (172u << 4 | 1u) || (a >> 16) == (192u << 8 | 168u) || (a >> 24) == 127 ||
           (a >> 22) == (100u << 2 | 1u); /* 100.64.0.0/10 */
}

int oc_apisrv_addr(const char *text, struct sockaddr_storage *out, socklen_t *len, char *err, size_t cap)
{
    char host[64];
    const char *colon;
    memset(out, 0, sizeof(*out));
    if (text[0] == '[') {
        const char *end = strchr(text, ']');
        if (end == NULL || end[1] != ':' || (size_t)(end - text - 1) >= sizeof(host)) goto bad;
        snprintf(host, sizeof(host), "%.*s", (int)(end - text - 1), text + 1);
        colon = end + 1;
    } else {
        colon = strrchr(text, ':');
        if (colon == NULL || (size_t)(colon - text) >= sizeof(host)) goto bad;
        snprintf(host, sizeof(host), "%.*s", (int)(colon - text), text);
    }
    char *end;
    long port = strtol(colon + 1, &end, 10);
    if (*end != '\0' || end == colon + 1 || port < 1 || port > 65535) goto bad;
    struct sockaddr_in *v4 = (struct sockaddr_in *)out;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
    if (text[0] != '[' && inet_pton(AF_INET, host, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons((uint16_t)port);
        *len = sizeof(*v4);
        if (!private4(ntohl(v4->sin_addr.s_addr))) goto public;
        return 0;
    }
    if (text[0] == '[' && inet_pton(AF_INET6, host, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons((uint16_t)port);
        *len = sizeof(*v6);
        if (!IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr) && (v6->sin6_addr.s6_addr[0] & 0xfe) != 0xfc) goto public;
        return 0;
    }
bad:
    snprintf(err, cap, "api_listen = '%s': ADDRESS:PORT, e.g. 10.0.0.60:7444 or [fd00::1]:7444", text);
    return -1;
public:
    snprintf(err, cap, "api_listen = '%s': not a private address (the admin API is never public)", text);
    return -1;
}

int oc_apisrv_open(oc_apisrv_t *s, const char *text, oc_tls_t *tls, oc_api_t *api, uint64_t (*now_us)(void),
                   char *err, size_t cap)
{
    struct sockaddr_storage sa;
    socklen_t len;
    memset(s, 0, sizeof(*s));
    s->lfd = -1;
    for (unsigned i = 0; i < OC_APISRV_CONNS; i++) s->c[i].tls.fd = -1;
    if (oc_apisrv_addr(text, &sa, &len, err, cap) != 0) return -1;
    int fd = socket(sa.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), one = 1;
    /* IP_FREEBIND: at boot the address (10.0.0.60) may not be up yet; the
     * core must start anyway (its cells too), and the listener takes the
     * connections once the address is there. */
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) != 0 ||
        bind(fd, (struct sockaddr *)&sa, len) != 0 || listen(fd, 8) != 0) {
        snprintf(err, cap, "api_listen = '%s': %s", text, strerror(errno));
        if (fd >= 0) close(fd);
        return -1;
    }
    s->lfd = fd;
    s->tls = tls;
    s->api = api;
    s->now_us = now_us;
    return 0;
}

static void conn_close(oc_apisrv_conn_t *c, int prio, const char *why)
{
    if (why != NULL) oc_log(prio, "api: %s: closed: %s", c->addr, why);
    oc_tls_conn_close(&c->tls);
    oc_buf_free(&c->tx); /* wiped: a QR code, say */
    oc_sig_wipe(c->rx, sizeof(c->rx));
    c->rn = c->toff = 0;
    c->state = C_FREE;
}

static void set_phase(oc_apisrv_t *s, oc_apisrv_conn_t *c)
{
    int p = c->state == C_HANDSHAKE ? P_HANDSHAKE : c->toff < c->tx.n ? P_ANSWER : c->rn > 0 ? P_FRAME : P_IDLE;
    if (p != c->phase) {
        c->phase = p;
        c->since_us = s->now_us();
    }
}

static void accept_one(oc_apisrv_t *s)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int fd = accept4(s->lfd, (struct sockaddr *)&sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;
    char addr[64] = "?";
    char host[INET6_ADDRSTRLEN] = "?";
    if (sa.ss_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr, host, sizeof(host));
        snprintf(addr, sizeof(addr), "%s:%u", host, ntohs(((struct sockaddr_in *)&sa)->sin_port));
    } else if (sa.ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sa)->sin6_addr, host, sizeof(host));
        snprintf(addr, sizeof(addr), "[%s]:%u", host, ntohs(((struct sockaddr_in6 *)&sa)->sin6_port));
    }
    oc_apisrv_conn_t *c = NULL;
    for (unsigned i = 0; i < OC_APISRV_CONNS && c == NULL; i++) {
        if (s->c[i].state == C_FREE) c = &s->c[i];
    }
    if (c == NULL) {
        uint64_t now = s->now_us();
        if (now - s->full_logged_us >= 10000000u || s->full_logged_us == 0) {
            oc_log(OC_LOG_WARNING, "api: %s: refused, %u connections open already", addr, OC_APISRV_CONNS);
            s->full_logged_us = now;
        }
        close(fd);
        return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    memset(c, 0, sizeof(*c));
    snprintf(c->addr, sizeof(c->addr), "%s", addr);
    if (oc_tls_conn_start(s->tls, &c->tls, fd) != 0) {
        oc_log(OC_LOG_ERR, "api: %s: no TLS session (out of memory?)", addr);
        c->tls.fd = -1;
        return;
    }
    c->state = C_HANDSHAKE;
    c->phase = P_HANDSHAKE;
    c->since_us = s->now_us();
}

/* Everything c can do now, up to OC_APISRV_BURST requests. */
static void conn_serve(oc_apisrv_t *s, oc_apisrv_conn_t *c)
{
    if (c->state == C_HANDSHAKE) {
        int r = oc_tls_conn_handshake(&c->tls);
        if (r < 0) {
            conn_close(c, OC_LOG_WARNING, c->tls.why);
            return;
        }
        if (r == 0) return;
        c->state = C_OPEN;
        oc_log(OC_LOG_INFO, "api: %s: connected, certificate %.16s...", c->addr, c->tls.peer);
    }
    for (unsigned served = 0; served < OC_APISRV_BURST;) {
        if (c->toff < c->tx.n) { /* the answer first */
            long w = oc_tls_conn_write(&c->tls, c->tx.p + c->toff, c->tx.n - c->toff);
            if (w < 0) {
                conn_close(c, OC_LOG_INFO, "the peer stopped reading (send failed)");
                return;
            }
            if (w == 0) break;
            c->toff += (size_t)w;
            continue;
        }
        if (c->tx.n > 0) {
            oc_buf_free(&c->tx);
            c->toff = 0;
        }
        if (c->rn >= 2) { /* a whole request read: served */
            size_t len = (size_t)c->rx[0] << 8 | c->rx[1];
            if (len == 0 || len + 2u > OC_API_FRAME_MAX) {
                conn_close(c, OC_LOG_WARNING, "a frame of an impossible length");
                return;
            }
            if (c->rn >= len + 2u) {
                int rc = oc_api_handle(s->api, c->rx, len + 2u, &c->tx);
                memmove(c->rx, c->rx + len + 2u, c->rn - len - 2u);
                c->rn -= len + 2u;
                oc_sig_wipe(c->rx + c->rn, sizeof(c->rx) - c->rn);
                if (rc != 0) {
                    conn_close(c, OC_LOG_WARNING, "not a request");
                    return;
                }
                if (c->tx.err) {
                    conn_close(c, OC_LOG_ERR, "out of memory for the answer");
                    return;
                }
                served++;
                set_phase(s, c);
                continue;
            }
        }
        long r = oc_tls_conn_read(&c->tls, c->rx + c->rn, sizeof(c->rx) - c->rn);
        if (r < 0) {
            conn_close(c, OC_LOG_INFO, "the peer closed it");
            return;
        }
        if (r == 0) break;
        c->rn += (size_t)r;
        set_phase(s, c);
    }
    /* The burst ended with an answer queued (its write never tried, so the
     * last SSL call wanted nothing): poll for writing, or it would wait for
     * input the client, waiting for that answer, never sends. */
    if (c->toff < c->tx.n && c->tls.want == POLLIN) c->tls.want = POLLOUT;
    set_phase(s, c);
}

unsigned oc_apisrv_fds(oc_apisrv_t *s, struct pollfd *p, int *timeout_ms)
{
    unsigned n = 0;
    if (s->lfd < 0) return 0;
    p[n++] = (struct pollfd){ s->lfd, POLLIN, 0 };
    for (unsigned i = 0; i < OC_APISRV_CONNS; i++) {
        oc_apisrv_conn_t *c = &s->c[i];
        if (c->state == C_FREE) continue;
        p[n++] = (struct pollfd){ c->tls.fd, c->tls.want, 0 };
        int ready = oc_tls_conn_pending(&c->tls) > 0 ||
                    (c->state == C_OPEN && c->toff >= c->tx.n && c->rn >= 2 &&
                     c->rn >= ((size_t)c->rx[0] << 8 | c->rx[1]) + 2u);
        if (ready) *timeout_ms = 0;
    }
    return n;
}

void oc_apisrv_serve(oc_apisrv_t *s, const struct pollfd *p, unsigned n)
{
    if (s->lfd < 0 || n == 0) return;
    if (p[0].revents & POLLIN) {
        for (int i = 0; i < 4; i++) accept_one(s); /* a few per turn: the rest wait in the backlog */
    }
    for (unsigned j = 1; j < n; j++) {
        for (unsigned i = 0; i < OC_APISRV_CONNS; i++) {
            oc_apisrv_conn_t *c = &s->c[i];
            if (c->state != C_FREE && c->tls.fd == p[j].fd && p[j].revents != 0) conn_serve(s, c);
        }
    }
    for (unsigned i = 0; i < OC_APISRV_CONNS; i++) {
        oc_apisrv_conn_t *c = &s->c[i];
        if (c->state == C_FREE) continue;
        if (c->state == C_OPEN && oc_tls_conn_pending(&c->tls) > 0) conn_serve(s, c); /* poll can't see these */
        else if (c->state == C_OPEN && c->toff >= c->tx.n && c->rn >= 2) conn_serve(s, c);
        if (c->state == C_FREE) continue;
        /* read after serving: conn_serve may have just started a phase, and
         * an earlier "now" would make its age wrap round to "too old" */
        uint64_t now = s->now_us();
        if (now - c->since_us >= (uint64_t)LIMIT_S[c->phase] * 1000000u) {
            char why[80];
            snprintf(why, sizeof(why), "%s took more than %u s", PHASE[c->phase], LIMIT_S[c->phase]);
            conn_close(c, c->phase == P_IDLE ? OC_LOG_INFO : OC_LOG_WARNING, why);
        }
    }
}

void oc_apisrv_close(oc_apisrv_t *s)
{
    for (unsigned i = 0; i < OC_APISRV_CONNS; i++) {
        if (s->c[i].state != C_FREE) conn_close(&s->c[i], OC_LOG_INFO, NULL);
    }
    if (s->lfd >= 0) close(s->lfd);
    s->lfd = -1;
}
