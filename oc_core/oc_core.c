#include "oc_core_int.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "oc_sig_crypto.h"
#include "oc_sig_keys.h" /* oc_sig_wipe */

uint32_t oc_core_unix(oc_core_t *k)
{
    return k->io.unix_now(k->io.ctx);
}

void oc_core_logf(oc_core_t *k, const char *fmt, ...)
{
    char line[160];
    va_list ap;
    if (k->io.log == NULL) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    k->io.log(k->io.ctx, line);
}

void oc_core_audit(oc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                   const char *detail)
{
    oc_core_audit_t a;
    memset(&a, 0, sizeof(a));
    a.ts = oc_core_unix(k);
    a.event = event;
    if (number != NULL) memcpy(a.number, number, OC_SIG_NUMBER_LEN);
    a.tmid = tmid;
    a.cell_id = cell_id;
    snprintf(a.detail, sizeof(a.detail), "%s", detail != NULL ? detail : "");
    if (k->st.audit_add(k->st.ctx, &a) != 0) oc_core_logf(k, "audit write FAILED (event %u)", event);
}

int oc_core_begin(oc_core_t *k)
{
    if (k->st.begin(k->st.ctx) == 0) return 0;
    k->st.commit(k->st.ctx); /* -1 by contract: it only closes the doomed transaction */
    oc_core_logf(k, "store: begin FAILED");
    return -1;
}

static oc_core_link_t *link_of(oc_core_t *k, uint32_t link)
{
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (k->links[i].used && k->links[i].link == link) return &k->links[i];
    }
    return NULL;
}

static oc_core_link_t *link_of_cell(oc_core_t *k, uint32_t cell_id)
{
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (k->links[i].used && k->links[i].cell_id == cell_id && cell_id != 0) return &k->links[i];
    }
    return NULL;
}

int oc_core_linked(const oc_core_t *k, uint32_t cell_id)
{
    return link_of_cell((oc_core_t *)k, cell_id) != NULL;
}

static int send_link(oc_core_t *k, oc_core_link_t *l, const oc_core_msg_t *m)
{
    l->last_tx = k->now;
    return k->io.send(k->io.ctx, l->link, m);
}

int oc_core_send(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m)
{
    oc_core_link_t *l = link_of_cell(k, cell_id);
    return l != NULL ? send_link(k, l, m) : -1;
}

/* A cell's link is gone: its calls go too (§7.9, "Done means": no
 * half-open call on the other side). Its locations stay until a new boot. */
static void cell_gone(oc_core_t *k, uint32_t cell_id, uint64_t now)
{
    (void)now;
    oc_core_logf(k, "cell %u: link down", (unsigned)cell_id);
    oc_core_sw_cell_gone(k, cell_id);
}

/* The core drops a link itself: the transport is told to close it. */
static void drop(oc_core_t *k, oc_core_link_t *l, uint64_t now)
{
    uint32_t cell = l->cell_id, link = l->link;
    l->used = 0;
    if (cell != 0) cell_gone(k, cell, now);
    if (k->io.close != NULL) k->io.close(k->io.ctx, link);
}

int oc_core_netkey_new(const oc_core_store_t *st, uint16_t key_id, uint16_t period_s, const uint8_t random32[32],
                       uint32_t unix_now)
{
    oc_core_netkey_t key;
    memset(&key, 0, sizeof(key));
    key.key_id = key_id;
    key.period_s = period_s;
    key.created = unix_now;
    memcpy(key.sk, random32, 32);
    int r = oc_sig_x25519_public(key.sk, key.pk) == 0 ? st->netkey_put(st->ctx, &key) : -1;
    oc_sig_wipe(key.sk, sizeof(key.sk));
    return r;
}

int oc_core_init(oc_core_t *k, const oc_core_io_t *io, const oc_core_store_t *st, const oc_core_route_t *route,
                 const oc_core_cfg_t *cfg)
{
    oc_core_netkey_t key;
    memset(k, 0, sizeof(*k));
    k->io = *io;
    k->st = *st;
    k->route = *route;
    k->cfg = *cfg;
    int r = k->st.netkey_get(k->st.ctx, cfg->key_id, &key); /* only asked whether it is there */
    oc_sig_wipe(key.sk, sizeof(key.sk));
    return r == 0 ? 0 : -1; /* none, or the store failed: no core either way */
}

void oc_core_link_up(oc_core_t *k, uint32_t link, uint64_t now_us)
{
    k->now = now_us;
    if (link_of(k, link) != NULL) return;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (!k->links[i].used) {
            oc_core_link_t *l = &k->links[i];
            memset(l, 0, sizeof(*l));
            l->used = 1;
            l->link = link;
            l->last_rx = l->last_tx = now_us;
            return;
        }
    }
    oc_core_logf(k, "link %u refused: no room", (unsigned)link);
    if (k->io.close != NULL) k->io.close(k->io.ctx, link);
}

void oc_core_link_down(oc_core_t *k, uint32_t link, uint64_t now_us)
{
    k->now = now_us;
    oc_core_link_t *l = link_of(k, link);
    if (l == NULL) return;
    uint32_t cell = l->cell_id;
    l->used = 0;
    if (cell != 0) cell_gone(k, cell, now_us);
}

/* CELL_CFG with list group list_id's channel list, if the group has one:
 * 0 (sent, or no list), or -1 when the list could not be read - then the
 * cell's link is dropped, so it re-HELLOs and gets its list then, rather
 * than running on without it. */
static int send_list(oc_core_t *k, oc_core_link_t *l, uint16_t list_id, uint64_t now)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CELL_CFG;
    if (list_id == 0) return 0;
    int got = k->st.list_get(k->st.ctx, list_id, &m.u.cell_cfg.list);
    if (got == OC_CORE_STORE_FAILED) {
        oc_core_logf(k, "cell %u: channel list %u read FAILED, link dropped", (unsigned)l->cell_id,
                     (unsigned)list_id);
        drop(k, l, now);
        return -1;
    }
    if (got == 0) send_link(k, l, &m);
    return 0;
}

static void on_hello(oc_core_t *k, oc_core_link_t *l, const oc_core_msg_t *m, uint64_t now)
{
    oc_core_cell_t c;
    oc_core_netkey_t key;
    oc_core_msg_t r;
    uint32_t id = m->u.hello.cell_id;
    uint8_t reason = 0;
    int got_cell = OC_CORE_STORE_NONE, got_key = OC_CORE_STORE_NONE;
    memset(&r, 0, sizeof(r));
    memset(&key, 0, sizeof(key));
    if (m->u.hello.proto != OC_CORE_PROTO) {
        reason = OC_CORE_NAK_VERSION;
    } else if (id == 0 || (got_cell = k->st.cell_get(k->st.ctx, id, &c)) == OC_CORE_STORE_NONE) {
        reason = OC_CORE_NAK_UNKNOWN_CELL;
    } else if (got_cell == 0 && !c.enabled) {
        reason = OC_CORE_NAK_DISABLED;
    } else if (got_cell == 0 && (got_key = k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key)) == OC_CORE_STORE_NONE) {
        reason = OC_CORE_NAK_DISABLED; /* the core itself can't serve: no network key */
    }
    oc_sig_wipe(key.sk, sizeof(key.sk)); /* only period_s is wanted from it */
    if (got_cell == OC_CORE_STORE_FAILED || got_key == OC_CORE_STORE_FAILED) {
        /* a store failure, not a verdict on the cell: no HELLO_NAK or
         * CELL_REJECT audit to say otherwise; the link closes, it retries */
        oc_core_logf(k, "cell %u: HELLO: %s read FAILED, link closed", (unsigned)id,
                     got_cell == OC_CORE_STORE_FAILED ? "cell" : "network key");
        drop(k, l, now);
        return;
    }
    if (reason != 0) {
        char d[48];
        snprintf(d, sizeof(d), "HELLO refused (%u)", reason);
        oc_core_audit(k, OC_CORE_AUDIT_CELL_REJECT, NULL, 0, id, d);
        oc_core_logf(k, "cell %u: %s", (unsigned)id, d);
        r.type = OC_CORE_HELLO_NAK;
        r.u.hello_nak.reason = reason;
        send_link(k, l, &r);
        drop(k, l, now);
        return;
    }
    oc_core_link_t *old = link_of_cell(k, id);
    if (old != NULL && old != l) drop(k, old, now); /* one link per cell: the newest wins */
    if (l->cell_id != 0 && l->cell_id != id) cell_gone(k, l->cell_id, now);
    if (c.boot_id != m->u.hello.boot_id) {
        /* the cell process restarted: its registrations and the vectors it
         * never used went with it (network-core spec §7.9) */
        k->st.loc_purge_cell(k->st.ctx, id);
        k->st.av_drop_cell(k->st.ctx, id);
        oc_core_sw_cell_gone(k, id);
        c.boot_id = m->u.hello.boot_id;
        oc_core_logf(k, "cell %u: new boot, its locations purged", (unsigned)id);
    }
    c.last_seen = oc_core_unix(k);
    k->st.cell_put(k->st.ctx, &c);
    l->cell_id = id;
    r.type = OC_CORE_HELLO_ACK;
    r.u.hello_ack.mode = c.mode;
    r.u.hello_ack.period_s = key.period_s;
    r.u.hello_ack.key_id = k->cfg.key_id;
    memcpy(r.u.hello_ack.echo_number, k->cfg.echo_number, OC_SIG_NUMBER_LEN);
    send_link(k, l, &r);
    send_list(k, l, c.list_id, now);
}

void oc_core_rx(oc_core_t *k, uint32_t link, const oc_core_msg_t *m, uint64_t now_us)
{
    k->now = now_us;
    oc_core_link_t *l = link_of(k, link);
    if (l == NULL) return;
    l->last_rx = now_us;
    if (m->type == OC_CORE_HELLO) {
        on_hello(k, l, m, now_us);
        return;
    }
    if (m->type == OC_CORE_PING) {
        oc_core_msg_t r;
        memset(&r, 0, sizeof(r));
        r.type = OC_CORE_PONG;
        send_link(k, l, &r);
        return;
    }
    if (l->cell_id == 0) return; /* nothing but HELLO before HELLO */
    switch (m->type) { /* each family goes to its own file: HSS, registry, switch */
    case OC_CORE_ACT_FWD:
    case OC_CORE_AV_REQ:
    case OC_CORE_RESYNC:
        oc_core_hss_rx(k, l->cell_id, m);
        break;
    case OC_CORE_LOC_UPDATE:
    case OC_CORE_LOC_PURGE:
        oc_core_reg_rx(k, l->cell_id, m);
        break;
    case OC_CORE_CALL_ROUTE:
    case OC_CORE_CALL_ALERT:
    case OC_CORE_CALL_ANSWER:
    case OC_CORE_CALL_RELEASE:
    case OC_CORE_MEDIA:
        oc_core_sw_rx(k, l->cell_id, m);
        break;
    default:
        break;
    }
}

void oc_core_tick(oc_core_t *k, uint64_t now_us)
{
    k->now = now_us;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        oc_core_link_t *l = &k->links[i];
        if (!l->used) continue;
        if (now_us - l->last_rx >= OC_CORE_DEAD_US) {
            oc_core_logf(k, "link %u: silent for 15 s", (unsigned)l->link);
            drop(k, l, now_us);
        } else if (now_us - l->last_tx >= OC_CORE_PING_US) {
            oc_core_msg_t p;
            memset(&p, 0, sizeof(p));
            p.type = OC_CORE_PING;
            send_link(k, l, &p);
        }
    }
    if (now_us >= k->prune_at) {
        k->prune_at = now_us + OC_CORE_US(3600);
        oc_core_reg_tick(k);
    }
    oc_core_sw_tick(k);
}

int oc_core_cell_add(oc_core_t *k, uint32_t cell_id, const char *name, uint8_t mode, uint16_t list_id)
{
    oc_core_cell_t c;
    /* only a cell known not to exist: one whose record could not be read
     * is not written over (oc_core_store.h) */
    if (cell_id == 0) return -1;
    int got = k->st.cell_get(k->st.ctx, cell_id, &c);
    if (got == 0) return -1;
    if (got != OC_CORE_STORE_NONE) return -2;
    memset(&c, 0, sizeof(c));
    c.cell_id = cell_id;
    snprintf(c.name, sizeof(c.name), "%s", name);
    c.mode = mode;
    c.enabled = 1;
    c.list_id = list_id;
    return k->st.cell_put(k->st.ctx, &c) == 0 ? 0 : -2;
}

int oc_core_cell_revoke(oc_core_t *k, uint32_t cell_id, uint64_t now_us)
{
    oc_core_cell_t c;
    k->now = now_us;
    if (k->st.cell_get(k->st.ctx, cell_id, &c) != 0) return -1;
    c.enabled = 0;
    if (k->st.cell_put(k->st.ctx, &c) != 0) return -1;
    oc_core_link_t *l = link_of_cell(k, cell_id);
    if (l != NULL) drop(k, l, now_us);
    return 0;
}

int oc_core_chan_list_set(oc_core_t *k, uint16_t list_id, const oc_sig_chan_list_t *list, uint64_t now_us)
{
    oc_sig_chan_list_t l, old;
    k->now = now_us;
    if (list_id == 0 || list->count > OC_SIG_CHAN_MAX) return -1;
    memset(&l, 0, sizeof(l));
    l.count = list->count;
    memcpy(l.freq_hz, list->freq_hz, sizeof(l.freq_hz[0]) * l.count);
    memcpy(l.flags, list->flags, l.count);
    int got = k->st.list_get(k->st.ctx, list_id, &old);
    if (got == OC_CORE_STORE_FAILED) return -1; /* a version that could go backwards: nothing changed */
    l.ver = got == 0 && old.ver != 255u ? (uint8_t)(old.ver + 1u) : 1u;
    if (k->st.list_put(k->st.ctx, list_id, &l) != 0) return -1;
    int pushed = 1;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        oc_core_link_t *ln = &k->links[i];
        oc_core_cell_t c;
        if (!ln->used || ln->cell_id == 0) continue;
        int got_c = k->st.cell_get(k->st.ctx, ln->cell_id, &c);
        if (got_c == OC_CORE_STORE_FAILED) { /* maybe in the group: it gets its list at its re-HELLO */
            oc_core_logf(k, "cell %u: cell read FAILED, channel list %u not sent, link dropped",
                         (unsigned)ln->cell_id, (unsigned)list_id);
            drop(k, ln, now_us);
            pushed = 0;
        } else if (got_c == 0 && c.list_id == list_id && send_list(k, ln, list_id, now_us) != 0) {
            pushed = 0;
        }
    }
    oc_core_logf(k, "channel list %u: version %u, %u entries%s", (unsigned)list_id, (unsigned)l.ver,
                 (unsigned)l.count, pushed ? "" : " (not pushed to every cell)");
    return pushed ? l.ver : -2;
}
