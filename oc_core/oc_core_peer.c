/* OCSS links (network-core spec §15.2; core test services spec §6): HELLO
 * and HELLO_ACK agree on who the peer is, PING keeps the link alive, and an
 * up link's call control goes to the switch. The transport has already
 * checked the peer's certificate (chain, core role, pinned SHA-256) and
 * says whose it is (core_id); HELLO must name the same core. */
#include "oc_core_int.h"

#include <stdio.h>
#include <string.h>

static oc_core_peer_t *peer_of(oc_core_t *k, uint32_t link)
{
    for (unsigned i = 0; i < OC_CORE_PEERS; i++) {
        if (k->peers[i].used && k->peers[i].link == link) return &k->peers[i];
    }
    return NULL;
}

static int send_peer(oc_core_t *k, oc_core_peer_t *p, const oc_core_msg_t *m)
{
    p->last_tx = k->now;
    return k->io.send(k->io.ctx, p->link, m);
}

int oc_core_peer_send(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m)
{
    for (unsigned i = 0; i < OC_CORE_PEERS; i++) {
        oc_core_peer_t *p = &k->peers[i];
        if (p->used && p->up && p->core_id == core_id) return send_peer(k, p, m);
    }
    return -1;
}

int oc_core_peer_linked(const oc_core_t *k, uint16_t core_id)
{
    for (unsigned i = 0; i < OC_CORE_PEERS; i++) {
        if (k->peers[i].used && k->peers[i].up && k->peers[i].core_id == core_id) return 1;
    }
    return 0;
}

/* Forgotten here (and its calls ended if it carried any); close: the core
 * dropped it, so the transport is told to close it. */
static void gone(oc_core_t *k, oc_core_peer_t *p, int close)
{
    uint32_t link = p->link;
    uint16_t id = p->core_id;
    int was_up = p->up;
    p->used = 0;
    if (was_up) {
        oc_core_logf(k, "peer %u: link down", (unsigned)id);
        oc_core_sw_peer_gone(k, id);
    }
    if (close && k->io.close != NULL) k->io.close(k->io.ctx, link);
}

static void hello_out(oc_core_t *k, oc_core_peer_t *p, uint8_t type)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.peer_hello.proto = OC_OCSS_PROTO; /* HELLO only: HELLO_ACK does not carry it */
    m.u.peer_hello.core_id = k->cfg.core_id;
    m.u.peer_hello.table_ver = 0; /* the block table is the config's: no signed table yet */
    send_peer(k, p, &m);
}

void oc_core_peer_up(oc_core_t *k, uint32_t link, uint16_t core_id, int dialer, uint64_t now_us)
{
    k->now = now_us;
    if (peer_of(k, link) != NULL) return;
    oc_core_peer_t *p = NULL;
    for (unsigned i = 0; i < OC_CORE_PEERS && p == NULL; i++) {
        if (!k->peers[i].used) p = &k->peers[i];
    }
    if (p == NULL) {
        oc_core_logf(k, "peer %u: link %u refused: no room", (unsigned)core_id, (unsigned)link);
        if (k->io.close != NULL) k->io.close(k->io.ctx, link);
        return;
    }
    memset(p, 0, sizeof(*p));
    p->used = 1;
    p->link = link;
    p->core_id = core_id;
    p->dialer = (uint8_t)(dialer != 0);
    p->since = p->last_rx = p->last_tx = now_us;
    if (p->dialer) hello_out(k, p, OC_OCSS_HELLO);
}

void oc_core_peer_down(oc_core_t *k, uint32_t link, uint64_t now_us)
{
    k->now = now_us;
    oc_core_peer_t *p = peer_of(k, link);
    if (p != NULL) gone(k, p, 0);
}

/* The peer is who its certificate says: the link is up. An older link to
 * the same core goes (the newest wins), with its calls. */
static void up(oc_core_t *k, oc_core_peer_t *p)
{
    for (unsigned i = 0; i < OC_CORE_PEERS; i++) {
        oc_core_peer_t *o = &k->peers[i];
        if (o != p && o->used && o->core_id == p->core_id) gone(k, o, 1);
    }
    p->up = 1;
    oc_core_logf(k, "peer %u: up (link %u, %s)", (unsigned)p->core_id, (unsigned)p->link,
                 p->dialer ? "dialled" : "accepted");
}

static void refuse(oc_core_t *k, oc_core_peer_t *p, uint8_t reason, unsigned claimed)
{
    char d[64];
    snprintf(d, sizeof(d), "core %u HELLO refused (%u)", claimed, (unsigned)reason);
    oc_core_audit(k, OC_CORE_AUDIT_PEER_REJECT, NULL, 0, 0, d);
    oc_core_logf(k, "peer %u: %s", (unsigned)p->core_id, d);
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_HELLO_NAK;
    m.u.hello_nak.reason = reason;
    send_peer(k, p, &m);
    gone(k, p, 1);
}

void oc_core_peer_rx(oc_core_t *k, uint32_t link, const oc_core_msg_t *m, uint64_t now_us)
{
    k->now = now_us;
    oc_core_peer_t *p = peer_of(k, link);
    if (p == NULL) return;
    p->last_rx = now_us;
    switch (m->type) {
    case OC_OCSS_HELLO:
        if (p->dialer || p->up) return; /* only the dialler says HELLO, once */
        if (m->u.peer_hello.proto != OC_OCSS_PROTO) {
            refuse(k, p, OC_OCSS_NAK_VERSION, m->u.peer_hello.core_id);
        } else if (m->u.peer_hello.core_id != p->core_id) {
            refuse(k, p, OC_OCSS_NAK_WRONG_CORE, m->u.peer_hello.core_id);
        } else {
            hello_out(k, p, OC_OCSS_HELLO_ACK);
            up(k, p);
        }
        return;
    case OC_OCSS_HELLO_ACK:
        if (!p->dialer || p->up) return;
        if (m->u.peer_hello.core_id != p->core_id) {
            refuse(k, p, OC_OCSS_NAK_WRONG_CORE, m->u.peer_hello.core_id);
        } else {
            up(k, p);
        }
        return;
    case OC_OCSS_HELLO_NAK:
        oc_core_logf(k, "peer %u: refused our HELLO (%u)", (unsigned)p->core_id, (unsigned)m->u.hello_nak.reason);
        gone(k, p, 1);
        return;
    case OC_OCSS_PING: {
        oc_core_msg_t r;
        memset(&r, 0, sizeof(r));
        r.type = OC_OCSS_PONG;
        send_peer(k, p, &r);
        return;
    }
    case OC_OCSS_CALL_SETUP:
    case OC_OCSS_CALL_ALERT:
    case OC_OCSS_CALL_ANSWER:
    case OC_OCSS_CALL_RELEASE:
    case OC_OCSS_MEDIA:
        if (p->up) oc_core_sw_peer_rx(k, p->core_id, m);
        return;
    default:
        return; /* PONG, and anything that is not OCSS */
    }
}

void oc_core_peer_tick(oc_core_t *k)
{
    for (unsigned i = 0; i < OC_CORE_PEERS; i++) {
        oc_core_peer_t *p = &k->peers[i];
        if (!p->used) continue;
        if (!p->up && k->now - p->since >= OC_CORE_SETUP_US) {
            oc_core_logf(k, "peer %u: no HELLO in 10 s", (unsigned)p->core_id);
            gone(k, p, 1);
        } else if (k->now - p->last_rx >= OC_CORE_DEAD_US) {
            oc_core_logf(k, "peer %u: silent for 15 s", (unsigned)p->core_id);
            gone(k, p, 1);
        } else if (k->now - p->last_tx >= OC_CORE_PING_US) {
            oc_core_msg_t m;
            memset(&m, 0, sizeof(m));
            m.type = OC_OCSS_PING;
            send_peer(k, p, &m);
        }
    }
}
