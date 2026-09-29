#include "lc_cell.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "lc_sig_keys.h"

static void logf_(lc_cell_t *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void logf_(lc_cell_t *c, const char *fmt, ...)
{
    char line[160];
    va_list ap;
    if (c->io.log == NULL) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    c->io.log(c->io.ctx, line);
}

static int to_core(lc_cell_t *c, lc_core_msg_t *m)
{
    if (!c->linked) return -1;
    c->last_tx = c->now;
    return c->io.core_send(c->io.ctx, m);
}

/* ---- the leg table and the registrations ---- */

static lc_cell_leg_t *leg_by_call(lc_cell_t *c, uint32_t call_id)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->legs[i].used && c->legs[i].call_id == call_id) return &c->legs[i];
    }
    return NULL;
}

static lc_cell_leg_t *leg_by_ref(lc_cell_t *c, uint32_t ref)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->legs[i].used && c->legs[i].ref == ref) return &c->legs[i];
    }
    return NULL;
}

static lc_cell_leg_t *leg_by_tmid(lc_cell_t *c, uint32_t tmid)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->legs[i].used && c->legs[i].tmid == tmid) return &c->legs[i];
    }
    return NULL;
}

static lc_cell_leg_t *leg_new(lc_cell_t *c, uint32_t call_id, uint32_t ref, uint32_t tmid)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (!c->legs[i].used) {
            lc_cell_leg_t *l = &c->legs[i];
            memset(l, 0, sizeof(*l));
            l->used = 1;
            l->call_id = call_id;
            l->ref = ref;
            l->tmid = tmid;
            return l;
        }
    }
    return NULL;
}

static lc_cell_reg_t *reg_of(lc_cell_t *c, uint32_t tmid, int create)
{
    lc_cell_reg_t *free_slot = NULL;
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->regs[i].used && c->regs[i].tmid == tmid) return &c->regs[i];
        if (!c->regs[i].used && free_slot == NULL) free_slot = &c->regs[i];
    }
    if (!create || free_slot == NULL) return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = 1;
    free_slot->tmid = tmid;
    return free_slot;
}

/* The registration is gone: its RAND and RES with it. */
static void reg_forget(lc_cell_t *c, uint32_t tmid)
{
    lc_cell_reg_t *r = reg_of(c, tmid, 0);
    if (r != NULL) lc_sig_wipe(r, sizeof(*r));
}

/* The session of tmid, if any (lc_sig_net's table, read only). */
static const lc_sig_net_sess_t *sess_of(const lc_cell_t *c, uint32_t tmid)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->net.s[i].used && c->net.s[i].tmid == tmid) return &c->net.s[i];
    }
    return NULL;
}

/* tmid's registration here is void (lc_sig_net_drop): a call it holds ends
 * with cause, and no LOC_UPDATE is sent for it again. No LOC_PURGE either:
 * a drop the core asked for (LOC_CANCEL) has its location gone already; so
 * has one for an activation (the activation deleted the number's location
 * in its transaction); and one for a newer registration of the same number
 * (registered()) is followed at once by that one's LOC_UPDATE, which moves
 * the location - a purge could only race it. */
static void drop(lc_cell_t *c, uint32_t tmid, uint8_t cause)
{
    reg_forget(c, tmid);
    lc_sig_net_drop(&c->net, tmid, cause, c->now);
}

/* The order in which tmid's last vector arrived here (0: none noted). */
static uint32_t av_seq_of(const lc_cell_t *c, uint32_t tmid)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->av_seen[i].seq != 0 && c->av_seen[i].tmid == tmid) return c->av_seen[i].seq;
    }
    return 0;
}

static void av_note(lc_cell_t *c, uint32_t tmid)
{
    lc_cell_av_seen_t *e = NULL;
    for (unsigned i = 0; i < LC_SIG_NET_TERMS && e == NULL; i++) {
        if (c->av_seen[i].seq != 0 && c->av_seen[i].tmid == tmid) e = &c->av_seen[i];
    }
    if (e == NULL) { /* a free entry (seq 0), else the oldest */
        e = &c->av_seen[0];
        for (unsigned i = 1; i < LC_SIG_NET_TERMS; i++) {
            if (c->av_seen[i].seq < e->seq) e = &c->av_seen[i];
        }
    }
    e->tmid = tmid;
    e->seq = ++c->av_count;
}

/* The registration's record here, if any (read only). */
static const lc_cell_reg_t *reg_find(const lc_cell_t *c, uint32_t tmid)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->regs[i].used && c->regs[i].tmid == tmid) return &c->regs[i];
    }
    return NULL;
}

/* Every other session registered here with number: the number is bound to
 * another terminal now (lc_sig_net_act_done's drop list, for the TMIDs the
 * core has no location of here to cancel). */
static void drop_number(lc_cell_t *c, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t except)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        const lc_sig_net_sess_t *s = &c->net.s[i];
        if (s->used && s->registered && s->tmid != except && memcmp(s->number, number, LC_SIG_NUMBER_LEN) == 0) {
            logf_(c, "terminal %08x: its number is bound elsewhere now, dropped", (unsigned)s->tmid);
            drop(c, s->tmid, LC_SIG_CAUSE_NET_FAILURE);
        }
    }
}

/* Another session registered here with number whose vector came later than
 * seq, if any: the number's newer binding. */
static int newer_holder(const lc_cell_t *c, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t except, uint32_t seq)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        const lc_sig_net_sess_t *s = &c->net.s[i];
        if (!s->used || !s->registered || s->tmid == except || memcmp(s->number, number, LC_SIG_NUMBER_LEN) != 0) {
            continue;
        }
        const lc_cell_reg_t *r = reg_find(c, s->tmid);
        if (r != NULL && r->av_seq > seq) return 1;
    }
    return 0;
}

/* The registration's proof (§7.7, §19.1): the vector's RAND and the RES the
 * terminal answered it with, which only the terminal can compute. */
static void loc_update(lc_cell_t *c, const lc_cell_reg_t *r)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_UPDATE;
    m.u.loc_update.tmid = r->tmid;
    memcpy(m.u.loc_update.number, r->number, LC_SIG_NUMBER_LEN);
    memcpy(m.u.loc_update.rand, r->rand, 16);
    memcpy(m.u.loc_update.res, r->res, 8);
    to_core(c, &m);
    lc_sig_wipe(m.u.loc_update.res, sizeof(m.u.loc_update.res));
}

static void call_msg(lc_cell_t *c, uint8_t type, uint32_t ref, uint8_t cause)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = ref;
    m.u.call.cause = cause;
    to_core(c, &m);
}

/* ---- lc_sig_net's io: the questions go to the core ---- */

static void n_act_req(void *ctx, uint32_t tmid, const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8])
{
    lc_cell_t *c = ctx;
    if (!c->ready) return; /* activation always needs the core: the terminal times out */
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_ACT_FWD;
    m.u.act_fwd.req = ++c->req;
    m.u.act_fwd.tmid = tmid;
    memcpy(m.u.act_fwd.token_id, token_id, 8);
    memcpy(m.u.act_fwd.pkt, pkt, 32);
    memcpy(m.u.act_fwd.tag, tag, 8);
    to_core(c, &m);
}

static void ask_av(lc_cell_t *c, uint32_t tmid)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.req = ++c->req;
    m.u.av_req.tmid = tmid;
    m.u.av_req.count = 1; /* no vector cache yet (plan 9) */
    to_core(c, &m);
}

static void n_av_req(void *ctx, uint32_t tmid)
{
    lc_cell_t *c = ctx;
    if (c->ready) ask_av(c, tmid); /* else asked when the core accepts HELLO, if still wanted */
}

static void n_resync_req(void *ctx, uint32_t tmid, const uint8_t rand[16], const uint8_t auts[14])
{
    lc_cell_t *c = ctx;
    if (!c->ready) {
        lc_sig_net_av_done(&c->net, tmid, LC_SIG_AV_UNAVAILABLE, NULL, NULL, c->now);
        return;
    }
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_RESYNC;
    m.u.resync.req = ++c->req;
    m.u.resync.tmid = tmid;
    memcpy(m.u.resync.rand, rand, 16);
    memcpy(m.u.resync.auts, auts, 14);
    to_core(c, &m);
}

static void n_registered(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                         const uint8_t res[8])
{
    lc_cell_t *c = ctx;
    /* The core issued this vector for number's binding at the time, so of
     * two sessions here with the same number (the number re-activated while
     * the core knew no location of the old one here, so no LOC_CANCEL came)
     * the one whose vector arrived later holds the newer binding. That is
     * usually this one; but a terminal can answer a vector drawn before the
     * re-activation after the new terminal has registered here - then this
     * registration is the stale one, and goes (its REG_ACK is out already:
     * the terminal's calls are refused until it registers again). */
    uint32_t seq = av_seq_of(c, tmid);
    if (newer_holder(c, number, tmid, seq)) {
        logf_(c, "terminal %08x: registered with an older vector than its number's holder, dropped", (unsigned)tmid);
        drop(c, tmid, LC_SIG_CAUSE_NET_FAILURE);
        return;
    }
    drop_number(c, number, tmid);
    lc_cell_reg_t *r = reg_of(c, tmid, 1);
    if (r == NULL) return;
    r->av_seq = seq;
    /* kept for as long as the registration: a registration made while the
     * core link was down is reported after the next HELLO_ACK (§7.10) */
    memcpy(r->number, number, LC_SIG_NUMBER_LEN);
    memcpy(r->rand, rand, 16);
    memcpy(r->res, res, 8);
    if (c->ready) loc_update(c, r);
}

static void n_unregistered(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    lc_cell_t *c = ctx;
    reg_forget(c, tmid);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_PURGE;
    m.u.loc_purge.tmid = tmid;
    memcpy(m.u.loc_purge.number, number, LC_SIG_NUMBER_LEN);
    if (c->ready) to_core(c, &m);
}

static int n_send(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    lc_cell_t *c = ctx;
    return c->io.radio_send(c->io.ctx, tmid, p, n);
}

static void n_channel(void *ctx, uint32_t tmid, int on)
{
    lc_cell_t *c = ctx;
    if (c->io.radio_channel != NULL) c->io.radio_channel(c->io.ctx, tmid, on);
}

static void n_call(void *ctx, const lc_sig_net_call_ev_t *e)
{
    lc_cell_t *c = ctx;
    lc_cell_leg_t *l = leg_by_call(c, e->call_id);
    switch (e->what) {
    case LC_SIG_NET_MO: { /* not a number registered here: the core routes it (§7.4) */
        lc_core_msg_t m;
        memset(&m, 0, sizeof(m));
        m.type = LC_CORE_CALL_ROUTE;
        m.u.call_route.leg_ref = e->call_id;
        memcpy(m.u.call_route.called, e->number, LC_SIG_NUMBER_LEN);
        if (!c->ready || lc_sig_net_number(&c->net, e->tmid, m.u.call_route.caller) != 0 ||
            leg_new(c, e->call_id, e->call_id, e->tmid) == NULL) {
            lc_sig_net_peer_release(&c->net, e->call_id, LC_SIG_CAUSE_NET_FAILURE, c->now);
            return;
        }
        to_core(c, &m);
        return;
    }
    /* both also come for the MT leg of a local call (peer_tmid set): that
     * one is switched here, and the core has no leg of it */
    case LC_SIG_NET_ALERTING:
        if (e->peer_tmid == 0 && l != NULL) call_msg(c, LC_CORE_CALL_ALERT, l->ref, 0);
        return;
    case LC_SIG_NET_ANSWERED:
        if (e->peer_tmid == 0 && l != NULL) call_msg(c, LC_CORE_CALL_ANSWER, l->ref, 0);
        return;
    case LC_SIG_NET_ENDED:
        if (l != NULL) {
            l->used = 0;
            call_msg(c, LC_CORE_CALL_RELEASE, l->ref, e->cause); /* the same cause on the other leg */
        }
        return;
    default: /* LOCAL: switched here, nothing for the core */
        return;
    }
}

static void n_log(void *ctx, const char *line)
{
    lc_cell_t *c = ctx;
    logf_(c, "%s", line);
}

void lc_cell_init(lc_cell_t *c, const lc_cell_io_t *io, const lc_cell_cfg_t *cfg)
{
    memset(c, 0, sizeof(*c));
    c->io = *io;
    c->cfg = *cfg;
    const lc_sig_net_io_t nio = { c,      n_act_req, n_av_req, n_resync_req, n_registered, n_unregistered,
                                  n_send, n_channel, n_call,   n_log };
    const lc_sig_net_cfg_t ncfg = { cfg->mode, cfg->period_s };
    lc_sig_net_init(&c->net, &nio, &ncfg);
}

/* ---- radio side ---- */

void lc_cell_ul(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us)
{
    c->now = now_us;
    lc_sig_net_heard(&c->net, tmid, now_us);
    if (n > 0 && (p[0] & 0xF0u) == LC_SIG_KIND_SIG) {
        lc_sig_net_rx(&c->net, tmid, p, n, now_us);
        return;
    }
    if (n == 0 || p[0] != LC_SIG_KIND_DATA) return;
    uint8_t d[LC_SIG_APP_MAX], dn, out[LC_SIG_LINK_MAX], on;
    uint32_t to = 0;
    if (lc_sig_net_local_peer(&c->net, tmid, &to)) { /* a local call: straight to the other leg */
        if (lc_sig_net_data_in(&c->net, tmid, p, n, d, &dn) == 0 && lc_sig_net_data_out(&c->net, to, d, dn, out, &on) == 0) {
            c->io.radio_send(c->io.ctx, to, out, on);
        }
        return;
    }
    lc_cell_leg_t *l = leg_by_tmid(c, tmid);
    if (l == NULL || lc_sig_net_data_in(&c->net, tmid, p, n, d, &dn) != 0) return;
    lc_core_msg_t m; /* to the far leg, in the clear inside the core link (§7.4 step 6) */
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_MEDIA;
    m.u.media.ref = l->ref;
    m.u.media.seq = l->seq++;
    m.u.media.len = dn;
    memcpy(m.u.media.data, d, dn);
    to_core(c, &m);
}

void lc_cell_upper(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us)
{
    c->now = now_us;
    if (n == 1 && (p[0] & 0xF0u) == LC_SIG_KIND_SVC) lc_sig_net_service_req(&c->net, tmid, p[0] & 0x0Fu, now_us);
}

void lc_cell_radio_link(lc_cell_t *c, uint32_t tmid, int granted, uint64_t now_us)
{
    c->now = now_us;
    lc_sig_net_link(&c->net, tmid, granted, now_us);
}

/* ---- core side ---- */

void lc_cell_core_up(lc_cell_t *c, uint64_t now_us)
{
    c->now = c->last_rx = c->last_tx = now_us;
    c->linked = 1;
    c->ready = 0;
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO;
    m.u.hello.proto = LC_CORE_PROTO;
    m.u.hello.cell_id = c->cfg.cell_id;
    m.u.hello.boot_id = c->cfg.boot_id;
    memcpy(m.u.hello.sw_version, c->cfg.sw_version, 3);
    to_core(c, &m);
}

/* §7.4 timers: with no core, every cross-cell leg ends at once (cause 5);
 * local calls and registrations go on. */
void lc_cell_core_down(lc_cell_t *c, uint64_t now_us)
{
    c->now = now_us;
    c->linked = 0;
    c->ready = 0;
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (!c->legs[i].used) continue;
        c->legs[i].used = 0;
        lc_sig_net_peer_release(&c->net, c->legs[i].call_id, LC_SIG_CAUSE_NET_FAILURE, now_us);
    }
}

static uint32_t tmid_of_call(const lc_cell_t *c, uint32_t call_id)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->net.s[i].used && c->net.s[i].call_id == call_id) return c->net.s[i].tmid;
    }
    return 0;
}

static void on_offer(lc_cell_t *c, const lc_core_msg_t *m)
{
    uint32_t cid = 0;
    uint32_t ref = m->u.call_offer.call_ref;
    int r = lc_sig_net_call_in(&c->net, m->u.call_offer.callee, m->u.call_offer.caller, c->now, &cid);
    if (r == 0 && leg_new(c, cid, ref, tmid_of_call(c, cid)) == NULL) { /* no room for the leg */
        lc_sig_net_peer_release(&c->net, cid, LC_SIG_CAUSE_NET_FAILURE, c->now);
        r = LC_SIG_NET_IN_UNREACHABLE;
    }
    if (r == LC_SIG_NET_IN_BUSY) call_msg(c, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_BUSY);
    if (r == LC_SIG_NET_IN_UNREACHABLE) call_msg(c, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_UNREACHABLE);
}

void lc_cell_core_rx(lc_cell_t *c, const lc_core_msg_t *m, uint64_t now_us)
{
    lc_cell_leg_t *l;
    c->now = c->last_rx = now_us;
    switch (m->type) {
    case LC_CORE_HELLO_ACK:
        c->ready = 1;
        c->net.cfg.mode = m->u.hello_ack.mode;
        c->net.cfg.period_s = m->u.hello_ack.period_s;
        memcpy(c->echo_number, m->u.hello_ack.echo_number, LC_SIG_NUMBER_LEN);
        for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) { /* the core may have lost them (§7.10, §14.6) */
            if (c->regs[i].used && lc_sig_net_registered(&c->net, c->regs[i].tmid)) loc_update(c, &c->regs[i]);
        }
        /* registrations that waited for the core. A RESYNC the link drop
         * lost is asked again as a plain AV_REQ: its vector fails with
         * AUTH_FAIL(2) once more and the RESYNC follows, one round later */
        for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
            const lc_sig_net_sess_t *s = &c->net.s[i];
            if (s->used && s->av_wait && now_us - s->av_at < LC_SIG_NET_ASK_US) ask_av(c, s->tmid);
        }
        logf_(c, "core: HELLO accepted");
        break;
    case LC_CORE_HELLO_NAK:
        logf_(c, "core: HELLO refused (%u)", m->u.hello_nak.reason);
        c->ready = 0;
        if (c->io.core_close != NULL) c->io.core_close(c->io.ctx);
        lc_cell_core_down(c, now_us);
        break;
    case LC_CORE_PING: {
        lc_core_msg_t p;
        memset(&p, 0, sizeof(p));
        p.type = LC_CORE_PONG;
        to_core(c, &p);
        break;
    }
    case LC_CORE_ACT_RES: {
        /* lc_sig_net_act_done's contract: every TMID of the activation's
         * drop list is dropped first. The core sends LOC_CANCEL(reactivated)
         * before ACT_RES for those it has a location of (so they are
         * dropped already: drop leaves the open activation question alone);
         * here, the ones registered here that it may not know of - the
         * activating terminal's previous life, and another terminal with
         * the number (registered while this cell was cut off). */
        uint32_t tmid = m->u.act_res.tmid;
        const lc_sig_net_sess_t *s = sess_of(c, tmid);
        const uint8_t *number = m->u.act_res.msg.u.act_ack.number;
        if (m->u.act_res.msg.type == LC_SIG_ACT_ACK && s != NULL && s->act_wait) {
            /* only for another number: an ACK for the number it is
             * registered with is an ACT_REQ answered again (a replay or a
             * retransmission: LC_SIG_ACT_AGAIN), which changes nothing. A
             * real re-activation of the same number the core had no
             * location of can't be told from one: that registration stays
             * until the terminal registers with its new keys, at once. */
            if (s->registered && memcmp(s->number, number, LC_SIG_NUMBER_LEN) != 0) {
                drop(c, tmid, LC_SIG_CAUSE_LINK_LOST);
            }
            drop_number(c, number, tmid);
        }
        lc_sig_net_act_done(&c->net, tmid, &m->u.act_res.msg, now_us);
        break;
    }
    case LC_CORE_AV_RES: {
        uint8_t st = m->u.av_res.status == LC_SIG_AV_OK && m->u.av_res.count == 0 ? LC_SIG_AV_UNAVAILABLE
                                                                                   : m->u.av_res.status;
        if (lc_sig_net_av_done(&c->net, m->u.av_res.tmid, st, m->u.av_res.number, &m->u.av_res.av[0], now_us) == 0 &&
            st == LC_SIG_AV_OK) {
            av_note(c, m->u.av_res.tmid);
        }
        break;
    }
    case LC_CORE_LOC_CANCEL: {
        /* A RAND names the registration cancelled: if it isn't this TMID's
         * registration here now, the cancel is late (the terminal came back
         * and registered again; that LOC_UPDATE is on its way), and it is
         * ignored. All zero: whatever it registered with. */
        static const uint8_t any[16] = { 0 };
        uint32_t tmid = m->u.loc_cancel.tmid;
        const lc_cell_reg_t *r = reg_find(c, tmid);
        int named = memcmp(m->u.loc_cancel.rand, any, 16) != 0;
        if (named && (r == NULL || memcmp(r->rand, m->u.loc_cancel.rand, 16) != 0)) {
            logf_(c, "core: LOC_CANCEL for an older registration of %08x ignored", (unsigned)tmid);
            break;
        }
        /* moved: as a lost link would (no handover); otherwise the network cut it */
        uint8_t cause = m->u.loc_cancel.cause == LC_CORE_CANCEL_MOVED ? LC_SIG_CAUSE_LINK_LOST : LC_SIG_CAUSE_NET_FAILURE;
        drop(c, tmid, cause);
        break;
    }
    case LC_CORE_CALL_OFFER:
        on_offer(c, m);
        break;
    case LC_CORE_CALL_ALERT:
        if ((l = leg_by_ref(c, m->u.call.ref)) != NULL) lc_sig_net_peer_alert(&c->net, l->call_id, now_us);
        break;
    case LC_CORE_CALL_ANSWER:
        if ((l = leg_by_ref(c, m->u.call.ref)) != NULL) lc_sig_net_peer_answer(&c->net, l->call_id, now_us);
        break;
    case LC_CORE_CALL_RELEASE:
        if ((l = leg_by_ref(c, m->u.call.ref)) != NULL) {
            l->used = 0; /* the core knows: its ENDED goes nowhere */
            lc_sig_net_peer_release(&c->net, l->call_id, m->u.call.cause, now_us);
        }
        break;
    case LC_CORE_MEDIA:
        if ((l = leg_by_ref(c, m->u.media.ref)) != NULL) {
            uint8_t out[LC_SIG_LINK_MAX], on;
            if (lc_sig_net_data_out(&c->net, l->tmid, m->u.media.data, m->u.media.len, out, &on) == 0) {
                c->io.radio_send(c->io.ctx, l->tmid, out, on);
            }
        }
        break;
    default:
        break;
    }
}

void lc_cell_tick(lc_cell_t *c, uint64_t now_us)
{
    c->now = now_us;
    lc_sig_net_tick(&c->net, now_us);
    if (!c->linked) return;
    if (now_us - c->last_rx >= LC_CELL_DEAD_US) {
        logf_(c, "core: silent for 15 s, link dropped");
        if (c->io.core_close != NULL) c->io.core_close(c->io.ctx);
        lc_cell_core_down(c, now_us);
    } else if (now_us - c->last_tx >= LC_CELL_PING_US) {
        lc_core_msg_t p;
        memset(&p, 0, sizeof(p));
        p.type = LC_CORE_PING;
        to_core(c, &p);
    }
}
