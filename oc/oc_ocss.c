#define _GNU_SOURCE
#include "oc_ocss.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "oc_conn.h" /* oc_backoff_next */
#include "oc_log.h"
#include "oc_sig_keys.h" /* oc_sig_wipe */

enum { C_FREE = 0, C_CONNECTING, C_HANDSHAKE, C_OPEN };

#define RESET_US 30000000ull /* a link open this long resets its peer's redial wait */

/* "HOST:PORT" or "[V6]:PORT", numeric only. 0 or -1. */
static int parse_addr(const char *text, struct sockaddr_storage *sa, socklen_t *len)
{
    char host[64], port[8];
    const char *colon;
    if (text[0] == '[') {
        const char *end = strchr(text, ']');
        if (end == NULL || end[1] != ':' || (size_t)(end - text - 1) >= sizeof(host)) return -1;
        snprintf(host, sizeof(host), "%.*s", (int)(end - text - 1), text + 1);
        colon = end + 1;
    } else {
        colon = strrchr(text, ':');
        if (colon == NULL || (size_t)(colon - text) >= sizeof(host)) return -1;
        snprintf(host, sizeof(host), "%.*s", (int)(colon - text), text);
    }
    if (strlen(colon + 1) == 0 || strlen(colon + 1) >= sizeof(port)) return -1;
    snprintf(port, sizeof(port), "%s", colon + 1);
    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai) != 0 || ai == NULL) return -1;
    memcpy(sa, ai->ai_addr, ai->ai_addrlen);
    *len = ai->ai_addrlen;
    freeaddrinfo(ai);
    return 0;
}

static oc_tls_t *tls_ctx(const oc_ocss_cfg_t *cfg, int client, char *err, size_t cap)
{
    oc_tls_cfg_t t;
    memset(&t, 0, sizeof(t));
    t.cert = cfg->cert;
    t.key = cfg->key;
    t.ca = cfg->ca;
    t.alpn = OC_OCSS_ALPN;
    t.role = OC_TLS_ROLE_CORE;
    t.client = client;
    for (unsigned i = 0; i < cfg->npeer && i < OC_TLS_PINS; i++) memcpy(t.pin[i], cfg->peer[i].fpr, 32);
    t.npin = cfg->npeer < OC_TLS_PINS ? cfg->npeer : OC_TLS_PINS;
    return oc_tls_new(&t, err, cap);
}

int oc_ocss_open(oc_ocss_t *s, const oc_ocss_cfg_t *cfg, char *err, size_t cap)
{
    struct sockaddr_storage sa;
    socklen_t len;
    memset(s, 0, sizeof(*s));
    s->lfd = -1;
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) s->c[i].tls.fd = -1;
    s->cfg = *cfg;
    if (cfg->npeer == 0 || cfg->npeer > OC_OCSS_PEERS) {
        snprintf(err, cap, "ocss: 1 to %u peers", OC_OCSS_PEERS);
        return -1;
    }
    int dials = 0;
    for (unsigned i = 0; i < cfg->npeer; i++) {
        if (cfg->peer[i].addr[0] == '\0') continue;
        dials = 1;
        if (parse_addr(cfg->peer[i].addr, &sa, &len) != 0) {
            snprintf(err, cap, "peer %u: address '%s': ADDRESS:PORT", cfg->peer[i].core_id, cfg->peer[i].addr);
            return -1;
        }
    }
    if (dials && (s->cli = tls_ctx(cfg, 1, err, cap)) == NULL) return -1;
    if (cfg->listen == NULL) return 0;
    if ((s->srv = tls_ctx(cfg, 0, err, cap)) == NULL) {
        oc_ocss_close(s);
        return -1;
    }
    if (parse_addr(cfg->listen, &sa, &len) != 0) {
        snprintf(err, cap, "ocss_listen = '%s': ADDRESS:PORT, e.g. 10.99.0.2:7443", cfg->listen);
        oc_ocss_close(s);
        return -1;
    }
    int fd = socket(sa.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), one = 1;
    /* IP_FREEBIND/IPV6_FREEBIND (review M5): the WireGuard address may come
     * up after the core starts, on either family. */
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        (sa.ss_family == AF_INET && setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) != 0) ||
        (sa.ss_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_FREEBIND, &one, sizeof(one)) != 0) ||
        bind(fd, (struct sockaddr *)&sa, len) != 0 || listen(fd, 8) != 0) {
        snprintf(err, cap, "ocss_listen = '%s': %s", cfg->listen, strerror(errno));
        if (fd >= 0) close(fd);
        oc_ocss_close(s);
        return -1;
    }
    struct sockaddr_storage got;
    socklen_t gl = sizeof(got);
    if (getsockname(fd, (struct sockaddr *)&got, &gl) == 0) {
        s->port = ntohs(got.ss_family == AF_INET ? ((struct sockaddr_in *)&got)->sin_port
                                                 : ((struct sockaddr_in6 *)&got)->sin6_port);
    }
    s->lfd = fd;
    return 0;
}

static int peer_index(const oc_ocss_t *s, uint16_t core_id)
{
    for (unsigned i = 0; i < s->cfg.npeer; i++) {
        if (s->cfg.peer[i].core_id == core_id) return (int)i;
    }
    return -1;
}

/* The peer whose pinned certificate the handshake showed, or -1. */
static int peer_by_fpr(const oc_ocss_t *s, const char *hex)
{
    uint8_t f[32];
    if (oc_tls_fpr_parse(hex, f) != 0) return -1;
    for (unsigned i = 0; i < s->cfg.npeer; i++) {
        if (memcmp(s->cfg.peer[i].fpr, f, 32) == 0) return (int)i;
    }
    return -1;
}

/* Closed and freed; an open link is reported to oc_core (report) and a
 * dialled one is dialled again after its wait. */
static void conn_end(oc_ocss_t *s, oc_ocss_conn_t *c, int report, int prio, const char *why)
{
    int was_open = c->state == C_OPEN;
    uint32_t link = c->link;
    if (why != NULL) oc_log(prio, "ocss: %s (core %u): closed: %s", c->addr, (unsigned)c->core_id, why);
    oc_tls_conn_close(&c->tls);
    oc_sig_wipe(c->rx, sizeof(c->rx));
    oc_sig_wipe(c->tx, sizeof(c->tx));
    if (c->dialled) {
        int i = peer_index(s, c->core_id);
        if (i >= 0) {
            s->backoff_ms[i] = oc_backoff_next(s->backoff_ms[i]);
            s->dial_at[i] = s->cfg.now_us() + (uint64_t)s->backoff_ms[i] * 1000u;
        }
    }
    memset(c, 0, sizeof(*c));
    c->tls.fd = -1;
    if (report && was_open) oc_core_peer_down(s->cfg.core, link, s->cfg.now_us());
}

static oc_ocss_conn_t *free_conn(oc_ocss_t *s)
{
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
        if (s->c[i].state == C_FREE) return &s->c[i];
    }
    return NULL;
}

static void addr_text(const struct sockaddr_storage *sa, char *out, size_t cap)
{
    char host[INET6_ADDRSTRLEN] = "?";
    if (sa->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, host, sizeof(host));
        snprintf(out, cap, "%s:%u", host, ntohs(((const struct sockaddr_in *)sa)->sin_port));
    } else if (sa->ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, host, sizeof(host));
        snprintf(out, cap, "[%s]:%u", host, ntohs(((const struct sockaddr_in6 *)sa)->sin6_port));
    } else {
        snprintf(out, cap, "?");
    }
}

/* addr's host part (no port), as addr_text wrote it ("HOST:PORT" or
 * "[V6]:PORT"). */
static void host_only(const char *addr, char *out, size_t cap)
{
    size_t n;
    if (addr[0] == '[') {
        const char *end = strchr(addr, ']');
        n = end != NULL ? (size_t)(end - addr - 1) : 0;
        addr++;
    } else {
        const char *colon = strrchr(addr, ':');
        n = colon != NULL ? (size_t)(colon - addr) : strlen(addr);
    }
    if (n >= cap) n = cap - 1;
    memcpy(out, addr, n);
    out[n] = '\0';
}

/* 1 if some other connection from host is already accepted and not yet
 * open (review M4): at most one handshake per source address at once, so
 * a host that can reach this core's listener can't hold every slot by
 * reconnecting without ever finishing TLS. */
static int handshaking_from(const oc_ocss_t *s, const char *host)
{
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
        const oc_ocss_conn_t *c = &s->c[i];
        if (c->state == C_FREE || c->state == C_OPEN || c->dialled) continue;
        char h[64];
        host_only(c->addr, h, sizeof(h));
        if (strcmp(h, host) == 0) return 1;
    }
    return 0;
}

static void accept_one(oc_ocss_t *s)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int fd = accept4(s->lfd, (struct sockaddr *)&sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;
    char addr[64], host[64];
    addr_text(&sa, addr, sizeof(addr));
    host_only(addr, host, sizeof(host));
    if (handshaking_from(s, host)) { /* review M4 */
        oc_log(OC_LOG_WARNING, "ocss: %s: refused, already handshaking from this address", addr);
        close(fd);
        return;
    }
    oc_ocss_conn_t *c = free_conn(s);
    if (c == NULL) {
        oc_log(OC_LOG_WARNING, "ocss: %s: refused, %u links open already", addr, OC_OCSS_CONNS);
        close(fd);
        return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    memset(c, 0, sizeof(*c));
    snprintf(c->addr, sizeof(c->addr), "%s", addr);
    if (oc_tls_conn_start(s->srv, &c->tls, fd) != 0) {
        c->tls.fd = -1;
        return;
    }
    c->state = C_HANDSHAKE;
    c->since_us = s->cfg.now_us();
}

static void dial(oc_ocss_t *s, unsigned i)
{
    struct sockaddr_storage sa;
    socklen_t len;
    const oc_ocss_peer_t *p = &s->cfg.peer[i];
    oc_ocss_conn_t *c = free_conn(s);
    int fd = -1, one = 1;
    if (c == NULL || parse_addr(p->addr, &sa, &len) != 0 ||
        (fd = socket(sa.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0) {
        s->dial_at[i] = s->cfg.now_us() + 1000000u; /* no room, or no socket: again in 1 s */
        return;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    memset(c, 0, sizeof(*c));
    c->tls.fd = fd;
    c->dialled = 1;
    c->core_id = p->core_id;
    c->since_us = s->cfg.now_us();
    snprintf(c->addr, sizeof(c->addr), "%s", p->addr);
    if (connect(fd, (struct sockaddr *)&sa, len) != 0 && errno != EINPROGRESS) {
        c->state = C_CONNECTING; /* so conn_end frees it */
        conn_end(s, c, 0, OC_LOG_INFO, strerror(errno));
        return;
    }
    c->state = C_CONNECTING;
}

/* The TCP connect finished: TLS starts (as the client). */
static void connected(oc_ocss_t *s, oc_ocss_conn_t *c)
{
    int e = 0;
    socklen_t el = sizeof(e);
    if (getsockopt(c->tls.fd, SOL_SOCKET, SO_ERROR, &e, &el) != 0 || e != 0) {
        conn_end(s, c, 0, OC_LOG_INFO, strerror(e != 0 ? e : errno));
        return;
    }
    int fd = c->tls.fd;
    if (oc_tls_conn_start(s->cli, &c->tls, fd) != 0) { /* fd closed by it */
        c->tls.fd = -1;
        conn_end(s, c, 0, OC_LOG_ERR, "no TLS session (out of memory?)");
        return;
    }
    c->state = C_HANDSHAKE;
}

static void opened(oc_ocss_t *s, oc_ocss_conn_t *c)
{
    int i = peer_by_fpr(s, c->tls.peer);
    if (i < 0 || (c->dialled && s->cfg.peer[i].core_id != c->core_id)) { /* oc_tls checked the pin: belt and braces */
        conn_end(s, c, 0, OC_LOG_WARNING, "the certificate is not the peer's");
        return;
    }
    /* review M2: "the lower core_id dials" (spec §7.1) - a peer this core
     * has an address for is one THIS core should dial; an inbound link
     * claiming to be it did not come from the dial it was owed. */
    if (!c->dialled && s->cfg.peer[i].addr[0] != '\0') {
        conn_end(s, c, 0, OC_LOG_WARNING, "this core dials that peer; an inbound link from it is refused");
        return;
    }
    c->core_id = s->cfg.peer[i].core_id;
    c->state = C_OPEN;
    c->since_us = s->cfg.now_us();
    c->link = s->cfg.new_link(s->cfg.ctx);
    oc_log(OC_LOG_NOTICE, "ocss: %s: core %u, certificate %.16s..., %s", c->addr, (unsigned)c->core_id, c->tls.peer,
           c->dialled ? "dialled" : "accepted");
    oc_core_peer_up(s->cfg.core, c->link, c->core_id, c->dialled, s->cfg.now_us());
}

static void flush(oc_ocss_conn_t *c)
{
    while (c->tn > 0 && !c->dead) {
        long w = oc_tls_conn_write(&c->tls, c->tx, c->tn);
        if (w < 0) {
            c->dead = 1;
            return;
        }
        if (w == 0) return;
        memmove(c->tx, c->tx + w, c->tn - (size_t)w);
        c->tn -= (size_t)w;
        oc_sig_wipe(c->tx + c->tn, (size_t)w);
    }
}

/* Every whole frame read goes to oc_core; stops if oc_core dropped the link
 * meanwhile (oc_ocss_drop freed c). */
static void read_frames(oc_ocss_t *s, oc_ocss_conn_t *c)
{
    uint32_t link = c->link;
    for (;;) {
        long r = oc_tls_conn_read(&c->tls, c->rx + c->rn, sizeof(c->rx) - c->rn);
        if (r < 0) {
            c->dead = 1;
            return;
        }
        if (r == 0) return;
        c->rn += (size_t)r;
        while (c->rn >= 2) {
            size_t len = (size_t)c->rx[0] << 8 | c->rx[1];
            if (len == 0 || len + 2u > OC_CORE_FRAME_MAX) {
                c->dead = 1;
                return;
            }
            if (c->rn < len + 2u) break;
            oc_core_msg_t m;
            if (oc_core_decode(c->rx, len + 2u, &m) == 0) {
                oc_core_peer_rx(s->cfg.core, link, &m, s->cfg.now_us());
            } else {
                c->bad++;
            }
            oc_sig_wipe(&m, sizeof(m));
            if (c->state != C_OPEN || c->link != link) return; /* dropped by oc_core */
            memmove(c->rx, c->rx + len + 2u, c->rn - len - 2u);
            c->rn -= len + 2u;
            oc_sig_wipe(c->rx + c->rn, len + 2u);
        }
    }
}

static void step(oc_ocss_t *s, oc_ocss_conn_t *c, short revents)
{
    if (c->state == C_CONNECTING) {
        if (revents & (POLLOUT | POLLERR | POLLHUP)) connected(s, c);
        if (c->state != C_HANDSHAKE) return;
    }
    if (c->state == C_HANDSHAKE) {
        int r = oc_tls_conn_handshake(&c->tls);
        if (r < 0) {
            conn_end(s, c, 0, OC_LOG_WARNING, c->tls.why[0] != '\0' ? c->tls.why : "handshake failed");
            return;
        }
        if (r == 0) return;
        opened(s, c);
        if (c->state != C_OPEN) return;
    }
    flush(c);
    if (c->state == C_OPEN && !c->dead) read_frames(s, c);
}

unsigned oc_ocss_fds(oc_ocss_t *s, struct pollfd *p, int *timeout_ms)
{
    unsigned n = 0;
    if (s->cfg.core == NULL) return 0; /* never opened: no OCSS */
    uint64_t now = s->cfg.now_us();
    if (s->lfd >= 0) p[n++] = (struct pollfd){ s->lfd, POLLIN, 0 };
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
        oc_ocss_conn_t *c = &s->c[i];
        if (c->state == C_FREE) continue;
        short ev = c->state == C_CONNECTING ? POLLOUT
                   : c->state == C_HANDSHAKE ? c->tls.want
                                             : (short)(POLLIN | c->tls.want | (c->tn > 0 ? POLLOUT : 0));
        p[n++] = (struct pollfd){ c->tls.fd, ev, 0 };
        if (c->dead || oc_tls_conn_pending(&c->tls) > 0) *timeout_ms = 0;
        if (c->state != C_OPEN) {
            uint64_t end = c->since_us + OC_OCSS_HANDSHAKE_S * 1000000ull;
            int ms = end > now ? (int)((end - now + 999u) / 1000u) : 0;
            if (ms < *timeout_ms) *timeout_ms = ms;
        }
    }
    for (unsigned i = 0; i < s->cfg.npeer; i++) {
        if (s->cfg.peer[i].addr[0] == '\0') continue;
        int ms = s->dial_at[i] > now ? (int)((s->dial_at[i] - now + 999u) / 1000u) : 0;
        if (ms < *timeout_ms) *timeout_ms = ms;
    }
    return n;
}

static int has_conn(const oc_ocss_t *s, uint16_t core_id)
{
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
        if (s->c[i].state != C_FREE && s->c[i].core_id == core_id) return 1;
    }
    return 0;
}

void oc_ocss_serve(oc_ocss_t *s, const struct pollfd *p, unsigned n)
{
    unsigned j = 0;
    if (s->cfg.core == NULL) return;
    if (s->lfd >= 0 && n > 0) {
        if (p[0].revents & POLLIN) {
            for (int i = 0; i < 4; i++) accept_one(s);
        }
        j = 1;
    }
    for (; j < n; j++) {
        for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
            oc_ocss_conn_t *c = &s->c[i];
            if (c->state != C_FREE && c->tls.fd == p[j].fd && p[j].revents != 0) step(s, c, p[j].revents);
        }
    }
    uint64_t now = s->cfg.now_us();
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
        oc_ocss_conn_t *c = &s->c[i];
        if (c->state == C_FREE) continue;
        if (c->state == C_OPEN && !c->dead && oc_tls_conn_pending(&c->tls) > 0) read_frames(s, c);
        if (c->state == C_FREE) continue;
        if (c->dead) {
            conn_end(s, c, 1, OC_LOG_WARNING, "the link failed");
        } else if (c->state != C_OPEN && now - c->since_us >= OC_OCSS_HANDSHAKE_S * 1000000ull) {
            conn_end(s, c, 0, OC_LOG_WARNING, "no open link in 5 s");
        } else if (c->state == C_OPEN && c->dialled && now - c->since_us >= RESET_US) {
            int k = peer_index(s, c->core_id);
            if (k >= 0) s->backoff_ms[k] = 0;
        }
    }
    for (unsigned i = 0; i < s->cfg.npeer; i++) {
        if (s->cfg.peer[i].addr[0] != '\0' && now >= s->dial_at[i] && !has_conn(s, s->cfg.peer[i].core_id)) dial(s, i);
    }
}

static oc_ocss_conn_t *by_link(oc_ocss_t *s, uint32_t link)
{
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
        if (s->c[i].state == C_OPEN && s->c[i].link == link) return &s->c[i];
    }
    return NULL;
}

int oc_ocss_owns(const oc_ocss_t *s, uint32_t link) { return by_link((oc_ocss_t *)s, link) != NULL; }

int oc_ocss_send(oc_ocss_t *s, uint32_t link, const oc_core_msg_t *m)
{
    oc_ocss_conn_t *c = by_link(s, link);
    uint8_t f[OC_CORE_FRAME_MAX];
    if (c == NULL || c->dead) return -1;
    size_t n = oc_core_encode(m, f, sizeof(f));
    if (n == 0) return -1;
    if (c->tn + n > sizeof(c->tx)) {
        oc_log(OC_LOG_WARNING, "ocss: core %u: the peer stopped reading", (unsigned)c->core_id);
        c->dead = 1;
        return -1;
    }
    memcpy(c->tx + c->tn, f, n);
    c->tn += n;
    oc_sig_wipe(f, n);
    flush(c);
    return c->dead ? -1 : 0;
}

void oc_ocss_drop(oc_ocss_t *s, uint32_t link)
{
    oc_ocss_conn_t *c = by_link(s, link);
    if (c == NULL) return;
    flush(c); /* a HELLO_NAK goes out first */
    conn_end(s, c, 0, OC_LOG_INFO, "dropped by the core");
}

void oc_ocss_close(oc_ocss_t *s)
{
    for (unsigned i = 0; i < OC_OCSS_CONNS; i++) {
        if (s->c[i].state != C_FREE) conn_end(s, &s->c[i], 1, OC_LOG_INFO, NULL);
    }
    if (s->lfd >= 0) close(s->lfd);
    s->lfd = -1;
    oc_tls_free(s->srv);
    oc_tls_free(s->cli);
    s->srv = s->cli = NULL;
}
