#include "lc_core_int.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "lc_sig_crypto.h"

uint32_t lc_core_unix(lc_core_t *k)
{
    return k->io.unix_now(k->io.ctx);
}

void lc_core_logf(lc_core_t *k, const char *fmt, ...)
{
    char line[160];
    va_list ap;
    if (k->io.log == NULL) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    k->io.log(k->io.ctx, line);
}

void lc_core_audit(lc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                   const char *detail)
{
    lc_core_audit_t a;
    memset(&a, 0, sizeof(a));
    a.ts = lc_core_unix(k);
    a.event = event;
    if (number != NULL) memcpy(a.number, number, LC_SIG_NUMBER_LEN);
    a.tmid = tmid;
    a.cell_id = cell_id;
    snprintf(a.detail, sizeof(a.detail), "%s", detail != NULL ? detail : "");
    if (k->st.audit_add(k->st.ctx, &a) != 0) lc_core_logf(k, "audit write FAILED (event %u)", event);
}

static lc_core_link_t *link_of(lc_core_t *k, uint32_t link)
{
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        if (k->links[i].used && k->links[i].link == link) return &k->links[i];
    }
    return NULL;
}

static lc_core_link_t *link_of_cell(lc_core_t *k, uint32_t cell_id)
{
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        if (k->links[i].used && k->links[i].cell_id == cell_id && cell_id != 0) return &k->links[i];
    }
    return NULL;
}

int lc_core_linked(const lc_core_t *k, uint32_t cell_id)
{
    return link_of_cell((lc_core_t *)k, cell_id) != NULL;
}

static int send_link(lc_core_t *k, lc_core_link_t *l, const lc_core_msg_t *m)
{
    l->last_tx = k->now;
    return k->io.send(k->io.ctx, l->link, m);
}

int lc_core_send(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    lc_core_link_t *l = link_of_cell(k, cell_id);
    return l != NULL ? send_link(k, l, m) : -1;
}

/* A cell's link is gone: its calls go too (§7.9, "Done means": no
 * half-open call on the other side). Its locations stay until a new boot. */
static void cell_gone(lc_core_t *k, uint32_t cell_id, uint64_t now)
{
    (void)now;
    lc_core_logf(k, "cell %u: link down", (unsigned)cell_id);
    lc_core_sw_cell_gone(k, cell_id);
}

/* The core drops a link itself: the transport is told to close it. */
static void drop(lc_core_t *k, lc_core_link_t *l, uint64_t now)
{
    uint32_t cell = l->cell_id, link = l->link;
    l->used = 0;
    if (cell != 0) cell_gone(k, cell, now);
    if (k->io.close != NULL) k->io.close(k->io.ctx, link);
}

int lc_core_netkey_new(const lc_core_store_t *st, uint16_t key_id, uint16_t period_s, const uint8_t random32[32],
                       uint32_t unix_now)
{
    lc_core_netkey_t key;
    memset(&key, 0, sizeof(key));
    key.key_id = key_id;
    key.period_s = period_s;
    key.created = unix_now;
    memcpy(key.sk, random32, 32);
    if (lc_sig_x25519_public(key.sk, key.pk) != 0) return -1;
    return st->netkey_put(st->ctx, &key);
}

int lc_core_init(lc_core_t *k, const lc_core_io_t *io, const lc_core_store_t *st, const lc_core_route_t *route,
                 const lc_core_cfg_t *cfg)
{
    lc_core_netkey_t key;
    memset(k, 0, sizeof(*k));
    k->io = *io;
    k->st = *st;
    k->route = *route;
    k->cfg = *cfg;
    return k->st.netkey_get(k->st.ctx, cfg->key_id, &key);
}

void lc_core_link_up(lc_core_t *k, uint32_t link, uint64_t now_us)
{
    k->now = now_us;
    if (link_of(k, link) != NULL) return;
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        if (!k->links[i].used) {
            lc_core_link_t *l = &k->links[i];
            memset(l, 0, sizeof(*l));
            l->used = 1;
            l->link = link;
            l->last_rx = l->last_tx = now_us;
            return;
        }
    }
    lc_core_logf(k, "link %u refused: no room", (unsigned)link);
    if (k->io.close != NULL) k->io.close(k->io.ctx, link);
}

void lc_core_link_down(lc_core_t *k, uint32_t link, uint64_t now_us)
{
    k->now = now_us;
    lc_core_link_t *l = link_of(k, link);
    if (l == NULL) return;
    uint32_t cell = l->cell_id;
    l->used = 0;
    if (cell != 0) cell_gone(k, cell, now_us);
}

static void on_hello(lc_core_t *k, lc_core_link_t *l, const lc_core_msg_t *m, uint64_t now)
{
    lc_core_cell_t c;
    lc_core_netkey_t key;
    lc_core_msg_t r;
    uint32_t id = m->u.hello.cell_id;
    uint8_t reason = 0;
    memset(&r, 0, sizeof(r));
    if (m->u.hello.proto != LC_CORE_PROTO) {
        reason = LC_CORE_NAK_VERSION;
    } else if (id == 0 || k->st.cell_get(k->st.ctx, id, &c) != 0) {
        reason = LC_CORE_NAK_UNKNOWN_CELL;
    } else if (!c.enabled) {
        reason = LC_CORE_NAK_DISABLED;
    } else if (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) != 0) {
        reason = LC_CORE_NAK_DISABLED; /* the core itself can't serve: no network key */
    }
    if (reason != 0) {
        char d[48];
        snprintf(d, sizeof(d), "HELLO refused (%u)", reason);
        lc_core_audit(k, LC_CORE_AUDIT_CELL_REJECT, NULL, 0, id, d);
        lc_core_logf(k, "cell %u: %s", (unsigned)id, d);
        r.type = LC_CORE_HELLO_NAK;
        r.u.hello_nak.reason = reason;
        send_link(k, l, &r);
        drop(k, l, now);
        return;
    }
    lc_core_link_t *old = link_of_cell(k, id);
    if (old != NULL && old != l) drop(k, old, now); /* one link per cell: the newest wins */
    if (l->cell_id != 0 && l->cell_id != id) cell_gone(k, l->cell_id, now);
    if (c.boot_id != m->u.hello.boot_id) {
        /* the cell process restarted: its registrations and the vectors it
         * never used went with it (network-core spec §7.9) */
        k->st.loc_purge_cell(k->st.ctx, id);
        k->st.av_drop_cell(k->st.ctx, id);
        lc_core_sw_cell_gone(k, id);
        c.boot_id = m->u.hello.boot_id;
        lc_core_logf(k, "cell %u: new boot, its locations purged", (unsigned)id);
    }
    c.last_seen = lc_core_unix(k);
    k->st.cell_put(k->st.ctx, &c);
    l->cell_id = id;
    r.type = LC_CORE_HELLO_ACK;
    r.u.hello_ack.mode = c.mode;
    r.u.hello_ack.period_s = key.period_s;
    r.u.hello_ack.key_id = k->cfg.key_id;
    memcpy(r.u.hello_ack.echo_number, k->cfg.echo_number, LC_SIG_NUMBER_LEN);
    send_link(k, l, &r);
}

void lc_core_rx(lc_core_t *k, uint32_t link, const lc_core_msg_t *m, uint64_t now_us)
{
    k->now = now_us;
    lc_core_link_t *l = link_of(k, link);
    if (l == NULL) return;
    l->last_rx = now_us;
    if (m->type == LC_CORE_HELLO) {
        on_hello(k, l, m, now_us);
        return;
    }
    if (m->type == LC_CORE_PING) {
        lc_core_msg_t r;
        memset(&r, 0, sizeof(r));
        r.type = LC_CORE_PONG;
        send_link(k, l, &r);
        return;
    }
    if (l->cell_id == 0) return; /* nothing but HELLO before HELLO */
    switch (m->type) { /* each family goes to its own file: HSS, registry, switch */
    case LC_CORE_ACT_FWD:
    case LC_CORE_AV_REQ:
    case LC_CORE_RESYNC:
        lc_core_hss_rx(k, l->cell_id, m);
        break;
    case LC_CORE_CALL_ROUTE:
    case LC_CORE_CALL_ALERT:
    case LC_CORE_CALL_ANSWER:
    case LC_CORE_CALL_RELEASE:
    case LC_CORE_MEDIA:
        lc_core_sw_rx(k, l->cell_id, m);
        break;
    default:
        break;
    }
}

void lc_core_tick(lc_core_t *k, uint64_t now_us)
{
    k->now = now_us;
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        lc_core_link_t *l = &k->links[i];
        if (!l->used) continue;
        if (now_us - l->last_rx >= LC_CORE_DEAD_US) {
            lc_core_logf(k, "link %u: silent for 15 s", (unsigned)l->link);
            drop(k, l, now_us);
        } else if (now_us - l->last_tx >= LC_CORE_PING_US) {
            lc_core_msg_t p;
            memset(&p, 0, sizeof(p));
            p.type = LC_CORE_PING;
            send_link(k, l, &p);
        }
    }
    lc_core_sw_tick(k);
}

int lc_core_cell_add(lc_core_t *k, uint32_t cell_id, const char *name, uint8_t mode, uint16_t list_id)
{
    lc_core_cell_t c;
    if (cell_id == 0 || k->st.cell_get(k->st.ctx, cell_id, &c) == 0) return -1;
    memset(&c, 0, sizeof(c));
    c.cell_id = cell_id;
    snprintf(c.name, sizeof(c.name), "%s", name);
    c.mode = mode;
    c.enabled = 1;
    c.list_id = list_id;
    return k->st.cell_put(k->st.ctx, &c);
}

int lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us)
{
    lc_core_cell_t c;
    k->now = now_us;
    if (k->st.cell_get(k->st.ctx, cell_id, &c) != 0) return -1;
    c.enabled = 0;
    if (k->st.cell_put(k->st.ctx, &c) != 0) return -1;
    lc_core_link_t *l = link_of_cell(k, cell_id);
    if (l != NULL) drop(k, l, now_us);
    return 0;
}
