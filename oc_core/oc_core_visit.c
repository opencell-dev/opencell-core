/* Visiting subscribers (OCSS spec 2026-11-01 §4): a terminal on one of this
 * core's cells whose number is homed on another core. This core (the
 * serving core) relays the cell's activation, vector, resync, location and
 * purge requests to the home core over OCSS and passes the answers back;
 * the home core keeps K, OPc, SQN, tokens and the location, and answers
 * LOCATE for calls. The other half - the home core serving a peer's relays
 * - is here too: it runs the same HSS and registry code as for its own
 * cells, with the serving core named as the requester. */
#include "oc_core_int.h"

#include <stdio.h>
#include <string.h>

#include "oc_sig_keys.h" /* oc_sig_wipe */

/* ---- the TMID -> home core cache (§4.1) ---- */

void oc_core_tmid_learn(oc_core_t *k, uint32_t tmid, uint16_t home)
{
    oc_core_tmid_t *e = NULL, *old = &k->tmids[0];
    if (tmid == 0) return;
    for (unsigned i = 0; i < OC_CORE_TMIDS && e == NULL; i++) {
        if (k->tmids[i].tmid == tmid) e = &k->tmids[i];
        if (k->tmids[i].used < old->used) old = &k->tmids[i];
    }
    if (e == NULL) e = old; /* a free entry has used 0: it is the oldest */
    e->tmid = tmid;
    e->home = home;
    e->used = k->now + 1u;
}

static int tmid_cached(oc_core_t *k, uint32_t tmid, uint16_t *home)
{
    for (unsigned i = 0; i < OC_CORE_TMIDS; i++) {
        if (k->tmids[i].tmid == tmid && tmid != 0) {
            k->tmids[i].used = k->now + 1u;
            *home = k->tmids[i].home;
            return 1;
        }
    }
    return 0;
}

/* tmid's home: 0 with *home set (this core's id, or a peer's), 1 unknown,
 * -1 the store failed. */
static int tmid_home(oc_core_t *k, uint32_t tmid, uint16_t *home)
{
    oc_core_sub_t s;
    if (tmid_cached(k, tmid, home)) return 0;
    memset(&s, 0, sizeof(s));
    int got = k->st.sub_by_tmid(k->st.ctx, tmid, &s);
    int ours = got == 0 && oc_core_home_number(k, s.number);
    oc_sig_wipe(s.k, sizeof(s.k));
    oc_sig_wipe(s.opc, sizeof(s.opc));
    if (got == OC_CORE_STORE_FAILED) return -1;
    if (ours) {
        *home = k->cfg.core_id;
        return 0;
    }
    return 1;
}

/* ---- the relay table ---- */

static oc_core_relay_t *relay_new(oc_core_t *k, uint8_t kind, uint16_t peer)
{
    for (unsigned i = 0; i < OC_CORE_RELAYS; i++) {
        oc_core_relay_t *r = &k->relays[i];
        if (r->used) continue;
        memset(r, 0, sizeof(*r));
        r->used = 1;
        r->kind = kind;
        r->peer = peer;
        for (int busy = 1; busy;) { /* an id no other relay holds (review M6) */
            do {
                r->id = ++k->next_relay;
            } while (r->id == 0);
            busy = 0;
            for (unsigned j = 0; j < OC_CORE_RELAYS; j++) busy |= j != i && k->relays[j].used && k->relays[j].id == r->id;
        }
        r->due = k->now + OC_CORE_RELAY_US;
        return r;
    }
    if (k->now >= k->relay_log_at) {
        oc_core_logf(k, "relay: no room (%u outstanding)", OC_CORE_RELAYS);
        k->relay_log_at = k->now + 1000000ull;
    }
    return NULL;
}

/* The relay waiting for req from peer (AV relays: asked of every peer, so
 * any peer may answer them). */
static oc_core_relay_t *relay_of(oc_core_t *k, uint8_t kind, uint16_t peer, uint16_t req)
{
    for (unsigned i = 0; i < OC_CORE_RELAYS; i++) {
        oc_core_relay_t *r = &k->relays[i];
        if (!r->used || r->kind != kind || r->id != req) continue;
        if (kind != OC_CORE_RELAY_AV) {
            if (r->peer == peer) return r;
            continue;
        }
        for (unsigned j = 0; j < OC_CORE_PEERS; j++) { /* AV: a peer asked, once (review M5) */
            if (r->asked[j] == peer && peer != 0) {
                r->asked[j] = 0;
                return r;
            }
        }
    }
    return NULL;
}

static void tmid_forget(oc_core_t *k, uint32_t tmid, uint16_t home)
{
    for (unsigned i = 0; i < OC_CORE_TMIDS; i++) {
        if (k->tmids[i].tmid == tmid && k->tmids[i].home == home) memset(&k->tmids[i], 0, sizeof(k->tmids[i]));
    }
}

static void relay_free(oc_core_relay_t *r)
{
    oc_sig_wipe(r, sizeof(*r));
}

static uint32_t serving_life(oc_core_t *k)
{
    oc_core_netkey_t key;
    uint32_t period = 1800u;
    if (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) == 0) period = key.period_s;
    oc_sig_wipe(key.sk, sizeof(key.sk));
    return 2u * period;
}

/* ---- the serving core: a cell's request for a number homed elsewhere ---- */

/* AV_RES to the cell (its own req), and the copy here wiped. */
static void av_to_cell(oc_core_t *k, const oc_core_relay_t *r, const oc_core_msg_t *in, uint8_t status)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_AV_RES;
    m.u.av_res.req = r->cell_req;
    m.u.av_res.tmid = r->tmid;
    m.u.av_res.status = status;
    if (in != NULL && status == OC_CORE_AV_OK) {
        memcpy(m.u.av_res.number, in->u.av_res.number, OC_SIG_NUMBER_LEN);
        m.u.av_res.count = in->u.av_res.count;
        memcpy(m.u.av_res.av, in->u.av_res.av, sizeof(m.u.av_res.av));
    }
    oc_core_send(k, r->cell, &m);
    oc_sig_wipe(&m, sizeof(m));
}

/* AV_REQ or RESYNC (rand, auts) from a cell: 1 when relayed. */
static int relay_av(oc_core_t *k, uint32_t cell, uint16_t req, uint32_t tmid, uint8_t count, const uint8_t *rand,
                    const uint8_t *auts)
{
    uint16_t home = 0;
    int h = tmid_home(k, tmid, &home);
    if (h < 0 || (h == 0 && home == k->cfg.core_id)) return 0; /* served here (a failed read answers UNAVAILABLE) */
    uint16_t ask[OC_CORE_PEERS];
    unsigned n = 0;
    if (h == 0) {
        if (!oc_core_peer_mob(k, home)) { /* its home is cut off (or too old): the terminal retries */
            oc_core_relay_t tmp;
            memset(&tmp, 0, sizeof(tmp));
            tmp.cell = cell;
            tmp.cell_req = req;
            tmp.tmid = tmid;
            av_to_cell(k, &tmp, NULL, OC_CORE_AV_UNAVAILABLE);
            return 1;
        }
        ask[n++] = home;
    } else { /* unknown here: every peer that can say (§4.1 rule 3) */
        for (unsigned i = 0; i < OC_CORE_PEERS; i++) {
            const oc_core_peer_t *p = &k->peers[i];
            if (p->used && p->up && p->proto >= OC_OCSS_PROTO_MOB) ask[n++] = p->core_id;
        }
        if (n == 0) return 0; /* nobody to ask: NOT_ACTIVATED from here, as before */
    }
    oc_core_relay_t *r = relay_new(k, OC_CORE_RELAY_AV, n == 1 ? ask[0] : 0);
    if (r == NULL) {
        oc_core_relay_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.cell = cell;
        tmp.cell_req = req;
        tmp.tmid = tmid;
        av_to_cell(k, &tmp, NULL, OC_CORE_AV_UNAVAILABLE);
        return 1;
    }
    r->cell = cell;
    r->cell_req = req;
    r->tmid = tmid;
    r->nwait = (uint8_t)n;
    r->best = OC_CORE_AV_NOT_ACTIVATED;
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    if (rand != NULL) {
        m.type = OC_OCSS_RESYNC_RELAY;
        m.u.resync_relay.req = r->id;
        m.u.resync_relay.tmid = tmid;
        memcpy(m.u.resync_relay.rand, rand, 16);
        memcpy(m.u.resync_relay.auts, auts, 14);
        m.u.resync_relay.cell = cell;
    } else {
        m.type = OC_OCSS_AV_RELAY;
        m.u.av_relay.req = r->id;
        m.u.av_relay.tmid = tmid;
        m.u.av_relay.count = count;
        m.u.av_relay.cell = cell;
    }
    for (unsigned i = 0; i < n; i++) {
        if (oc_core_peer_send(k, ask[i], &m) != 0) {
            r->nwait--;
        } else {
            r->asked[i] = ask[i];
        }
    }
    if (r->nwait == 0) {
        av_to_cell(k, r, NULL, OC_CORE_AV_UNAVAILABLE);
        relay_free(r);
    }
    return 1;
}

static int relay_act(oc_core_t *k, uint32_t cell, const oc_core_msg_t *in)
{
    const oc_core_block_t *b = oc_core_route_block(&k->route, oc_core_token_block(in->u.act_fwd.token_id));
    if (b == NULL || oc_core_route_home(&k->route, b)) return 0;
    if (!oc_core_peer_mob(k, b->home_core)) { /* no answer: the terminal retries (plan-5 §4.4) */
        oc_core_logf(k, "activation of %08x: home core %u not linked", (unsigned)in->u.act_fwd.tmid,
                     (unsigned)b->home_core);
        return 1;
    }
    oc_core_relay_t *r = relay_new(k, OC_CORE_RELAY_ACT, b->home_core);
    if (r == NULL) return 1;
    r->cell = cell;
    r->cell_req = in->u.act_fwd.req;
    r->tmid = in->u.act_fwd.tmid;
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_ACT_RELAY;
    m.u.act_relay.req = r->id;
    m.u.act_relay.tmid = r->tmid;
    memcpy(m.u.act_relay.token_id, in->u.act_fwd.token_id, 8);
    memcpy(m.u.act_relay.pkt, in->u.act_fwd.pkt, 32);
    memcpy(m.u.act_relay.tag, in->u.act_fwd.tag, 8);
    m.u.act_relay.cell = cell;
    if (oc_core_peer_send(k, b->home_core, &m) != 0) relay_free(r);
    return 1;
}

static int relay_loc(oc_core_t *k, uint32_t cell, const oc_core_msg_t *in)
{
    const uint8_t *num = in->u.loc_update.number;
    const oc_core_block_t *b = oc_core_route_find(&k->route, num);
    if (b == NULL || oc_core_route_home(&k->route, b)) return 0;
    if (!oc_core_peer_mob(k, b->home_core)) {
        oc_core_logf(k, "cell %u: location of %08x: home core %u not linked", (unsigned)cell,
                     (unsigned)in->u.loc_update.tmid, (unsigned)b->home_core);
        return 1; /* the cell sends it again after its next HELLO_ACK */
    }
    oc_core_relay_t *r = relay_new(k, OC_CORE_RELAY_LOC, b->home_core);
    if (r == NULL) return 1;
    r->cell = cell;
    r->tmid = in->u.loc_update.tmid;
    memcpy(r->number, num, OC_SIG_NUMBER_LEN);
    memcpy(r->rand, in->u.loc_update.rand, 16);
    r->life_s = serving_life(k);
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_LOC_UPDATE;
    m.u.peer_loc.req = r->id;
    m.u.peer_loc.tmid = r->tmid;
    memcpy(m.u.peer_loc.number, num, OC_SIG_NUMBER_LEN);
    memcpy(m.u.peer_loc.rand, in->u.loc_update.rand, 16);
    memcpy(m.u.peer_loc.res, in->u.loc_update.res, 8);
    m.u.peer_loc.cell = cell;
    m.u.peer_loc.life_s = r->life_s;
    if (oc_core_peer_send(k, b->home_core, &m) != 0) relay_free(r);
    oc_sig_wipe(m.u.peer_loc.res, sizeof(m.u.peer_loc.res));
    return 1;
}

static int relay_purge(oc_core_t *k, uint32_t cell, const oc_core_msg_t *in)
{
    const uint8_t *num = in->u.loc_purge.number;
    const oc_core_block_t *b = oc_core_route_find(&k->route, num);
    if (b == NULL || oc_core_route_home(&k->route, b)) return 0;
    oc_core_reg_purge(k, 0, cell, in->u.loc_purge.tmid, num); /* the visitor row */
    if (oc_core_peer_mob(k, b->home_core)) {
        oc_core_msg_t m;
        memset(&m, 0, sizeof(m));
        m.type = OC_OCSS_LOC_PURGE;
        m.u.peer_purge.tmid = in->u.loc_purge.tmid;
        memcpy(m.u.peer_purge.number, num, OC_SIG_NUMBER_LEN);
        m.u.peer_purge.cell = cell;
        oc_core_peer_send(k, b->home_core, &m);
    }
    return 1;
}

int oc_core_visit_cell_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m)
{
    switch (m->type) {
    case OC_CORE_ACT_FWD: return relay_act(k, cell_id, m);
    case OC_CORE_AV_REQ:
        return relay_av(k, cell_id, m->u.av_req.req, m->u.av_req.tmid, m->u.av_req.count, NULL, NULL);
    case OC_CORE_RESYNC:
        return relay_av(k, cell_id, m->u.resync.req, m->u.resync.tmid, 1, m->u.resync.rand, m->u.resync.auts);
    case OC_CORE_LOC_UPDATE: return relay_loc(k, cell_id, m);
    case OC_CORE_LOC_PURGE: return relay_purge(k, cell_id, m);
    default: return 0;
    }
}

/* ---- the serving core: the home core's answers ---- */

static void on_act_res(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    oc_core_relay_t *r = relay_of(k, OC_CORE_RELAY_ACT, peer, m->u.act_res.req);
    if (r == NULL || r->tmid != m->u.act_res.tmid) return; /* late, or not ours */
    oc_core_msg_t out = *m;
    out.type = OC_CORE_ACT_RES;
    out.u.act_res.req = r->cell_req;
    oc_core_send(k, r->cell, &out);
    if (m->u.act_res.msg.type == OC_SIG_ACT_ACK) oc_core_tmid_learn(k, r->tmid, peer);
    relay_free(r);
}

/* A stronger answer than the one held, of several peers' (§4.3). */
static int rank(uint8_t st)
{
    switch (st) {
    case OC_CORE_AV_OK: return 5;
    case OC_CORE_AV_DISABLED: return 4;
    case OC_CORE_AV_UNAVAILABLE: return 3;
    case OC_CORE_AV_AUTH_FAILED: return 2;
    default: return 1;
    }
}

static void on_av_res(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    oc_core_relay_t *r = relay_of(k, OC_CORE_RELAY_AV, peer, m->u.av_res.req);
    if (r == NULL || r->tmid != m->u.av_res.tmid) return;
    if (m->u.av_res.status == OC_CORE_AV_OK) {
        av_to_cell(k, r, m, OC_CORE_AV_OK);
        oc_core_tmid_learn(k, r->tmid, peer);
        relay_free(r);
        return;
    }
    if (m->u.av_res.status == OC_CORE_AV_NOT_ACTIVATED) {
        tmid_forget(k, r->tmid, peer); /* review M4: a stale cached home; the next ask goes to every peer */
    }
    if (rank(m->u.av_res.status) > rank(r->best)) r->best = m->u.av_res.status;
    if (r->nwait > 0) r->nwait--;
    if (r->nwait == 0) {
        av_to_cell(k, r, NULL, r->best);
        relay_free(r);
    }
}

static void on_loc_ack(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    oc_core_relay_t *r = relay_of(k, OC_CORE_RELAY_LOC, peer, m->u.loc_ack.req);
    if (r == NULL || r->tmid != m->u.loc_ack.tmid || memcmp(r->number, m->u.loc_ack.number, OC_SIG_NUMBER_LEN) != 0) {
        return;
    }
    if (m->u.loc_ack.status == 0) { /* accepted: the visitor row, on this core's cell (core 0) */
        oc_core_loc_t old, l;
        int got = k->st.loc_get(k->st.ctx, r->number, &old);
        int changed = got != 0 || old.cell_id != r->cell || old.tmid != r->tmid || old.expires <= oc_core_unix(k);
        memset(&l, 0, sizeof(l));
        memcpy(l.number, r->number, OC_SIG_NUMBER_LEN);
        l.cell_id = r->cell;
        l.tmid = r->tmid;
        l.expires = oc_core_unix(k) + r->life_s;
        memcpy(l.rand, r->rand, 16);
        if (k->st.loc_put(k->st.ctx, &l) != 0) {
            oc_core_logf(k, "visitor %08x: location store FAILED", (unsigned)r->tmid);
        } else if (changed) {
            char d[40];
            snprintf(d, sizeof(d), "visitor, home core %u", (unsigned)peer);
            oc_core_audit(k, OC_CORE_AUDIT_REGISTER, r->number, r->tmid, r->cell, d);
        }
    }
    relay_free(r);
}

/* The home core cancels its subscriber's registration on one of this
 * core's cells: only the home of the number's block may. */
static void on_peer_cancel(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    const oc_core_block_t *b = oc_core_route_find(&k->route, m->u.peer_cancel.number);
    if (b == NULL || b->home_core != peer) {
        char d[48];
        snprintf(d, sizeof(d), "core %u LOC_CANCEL not its number", (unsigned)peer);
        oc_core_audit(k, OC_CORE_AUDIT_PEER_REJECT, m->u.peer_cancel.number, m->u.peer_cancel.tmid, 0, d);
        oc_core_logf(k, "peer %u: %s", (unsigned)peer, d);
        return;
    }
    /* Review I2: the cell is told only about the home's own registration -
     * the visitor row it names, or (the row already gone, or never made: a
     * refused claim) a TMID that is not bound to one of this core's own
     * subscribers - never to drop someone else's terminal. */
    oc_core_loc_t l;
    int got = k->st.loc_get(k->st.ctx, m->u.peer_cancel.number, &l);
    int row = got == 0 && l.core == 0 && l.cell_id == m->u.peer_cancel.cell && l.tmid == m->u.peer_cancel.tmid;
    if (!row) {
        oc_core_sub_t s;
        memset(&s, 0, sizeof(s));
        int bound = k->st.sub_by_tmid(k->st.ctx, m->u.peer_cancel.tmid, &s);
        int ours = bound == 0 && memcmp(s.number, m->u.peer_cancel.number, OC_SIG_NUMBER_LEN) != 0;
        oc_sig_wipe(s.k, sizeof(s.k));
        oc_sig_wipe(s.opc, sizeof(s.opc));
        if (got == OC_CORE_STORE_FAILED || bound == OC_CORE_STORE_FAILED || ours) {
            char d[48];
            snprintf(d, sizeof(d), "core %u LOC_CANCEL for a TMID not its", (unsigned)peer);
            oc_core_audit(k, OC_CORE_AUDIT_PEER_REJECT, m->u.peer_cancel.number, m->u.peer_cancel.tmid,
                          m->u.peer_cancel.cell, d);
            oc_core_logf(k, "peer %u: %s", (unsigned)peer, d);
            return;
        }
    } else if (k->st.loc_del(k->st.ctx, m->u.peer_cancel.number) != 0) {
        oc_core_logf(k, "visitor %08x: location delete failed", (unsigned)l.tmid);
    }
    oc_core_msg_t out;
    memset(&out, 0, sizeof(out));
    out.type = OC_CORE_LOC_CANCEL;
    out.u.loc_cancel.tmid = m->u.peer_cancel.tmid;
    out.u.loc_cancel.cause = m->u.peer_cancel.cause;
    memcpy(out.u.loc_cancel.rand, m->u.peer_cancel.rand, 16);
    if (oc_core_send(k, m->u.peer_cancel.cell, &out) != 0) {
        oc_core_logf(k, "cell %u: LOC_CANCEL from core %u not sent (no link)", (unsigned)m->u.peer_cancel.cell,
                     (unsigned)peer);
    }
}

/* ---- the home core: a serving core's relays ---- */

static void on_peer_loc(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    oc_core_msg_t a;
    memset(&a, 0, sizeof(a));
    a.type = OC_OCSS_LOC_ACK;
    a.u.loc_ack.req = m->u.peer_loc.req;
    a.u.loc_ack.tmid = m->u.peer_loc.tmid;
    memcpy(a.u.loc_ack.number, m->u.peer_loc.number, OC_SIG_NUMBER_LEN);
    a.u.loc_ack.status = 1;
    if (oc_core_home_number(k, m->u.peer_loc.number)) {
        if (oc_core_reg_update(k, peer, m->u.peer_loc.cell, m->u.peer_loc.tmid, m->u.peer_loc.number,
                               m->u.peer_loc.rand, m->u.peer_loc.res, m->u.peer_loc.life_s)) {
            a.u.loc_ack.status = 0;
        }
    } else {
        oc_core_logf(k, "peer %u: LOC_UPDATE for a number not homed here", (unsigned)peer);
    }
    oc_core_peer_send(k, peer, &a);
}

static void on_locate(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    oc_core_msg_t a;
    oc_core_sub_t s;
    oc_core_loc_t l;
    const uint8_t *num = m->u.locate.number;
    memset(&a, 0, sizeof(a));
    memset(&s, 0, sizeof(s));
    a.type = OC_OCSS_LOCATE_RES;
    a.u.locate_res.req = m->u.locate.req;
    memcpy(a.u.locate_res.number, num, OC_SIG_NUMBER_LEN);
    a.u.locate_res.status = OC_OCSS_LOC_NOT_REACHABLE;
    int got;
    if (oc_core_number_service(k, num)) {
        a.u.locate_res.status = OC_OCSS_LOC_OK;
        a.u.locate_res.core = k->cfg.core_id;
    } else if (!oc_core_home_number(k, num)) {
        a.u.locate_res.status = OC_OCSS_LOC_NOT_HOME;
    } else if ((got = k->st.sub_get(k->st.ctx, num, &s)) == OC_CORE_STORE_FAILED) {
        a.u.locate_res.status = OC_OCSS_LOC_UNAVAILABLE;
    } else if (got == 0 && s.state == OC_CORE_SUB_ACTIVE && s.activated) {
        got = oc_core_loc_live(k, num, &l);
        if (got == OC_CORE_STORE_FAILED) {
            a.u.locate_res.status = OC_OCSS_LOC_UNAVAILABLE;
        } else if (got == 0) {
            a.u.locate_res.status = OC_OCSS_LOC_OK;
            a.u.locate_res.core = l.core != 0 ? l.core : k->cfg.core_id;
            a.u.locate_res.cell = l.cell_id;
            a.u.locate_res.tmid = l.tmid;
        }
    }
    oc_sig_wipe(s.k, sizeof(s.k));
    oc_sig_wipe(s.opc, sizeof(s.opc));
    oc_core_peer_send(k, peer, &a);
}

static void on_peer_cdr(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    if (!oc_core_home_number(k, m->u.cdr.caller) && !oc_core_home_number(k, m->u.cdr.called)) {
        oc_core_logf(k, "peer %u: CDR for numbers not homed here: dropped", (unsigned)peer);
        return;
    }
    oc_core_cdr_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.caller, m->u.cdr.caller, OC_SIG_NUMBER_LEN);
    memcpy(r.called, m->u.cdr.called, OC_SIG_NUMBER_LEN);
    r.setup = m->u.cdr.setup;
    r.answer = m->u.cdr.answer;
    r.end = m->u.cdr.end;
    r.cause = m->u.cdr.cause;
    if (k->st.cdr_add(k->st.ctx, &r) != 0) oc_core_logf(k, "peer %u: CDR write FAILED", (unsigned)peer);
}

/* Another core bound tmid by an activation: a subscriber here still bound
 * to it lets it go, as a re-activation here would (network-core §7.1). */
static void on_bound(oc_core_t *k, uint16_t peer, uint32_t tmid)
{
    oc_core_sub_t s;
    oc_core_loc_t l;
    memset(&s, 0, sizeof(s));
    oc_core_tmid_learn(k, tmid, peer);
    if (k->st.sub_by_tmid(k->st.ctx, tmid, &s) == 0) {
        int got = k->st.loc_get(k->st.ctx, s.number, &l);
        if (got != OC_CORE_STORE_FAILED && oc_core_begin(k) == 0) {
            s.activated = 0;
            s.tmid = 0;
            s.updated = oc_core_unix(k);
            k->st.sub_put(k->st.ctx, &s);
            if (got == 0) k->st.loc_del(k->st.ctx, s.number);
            k->st.av_del_number(k->st.ctx, s.number);
            if (k->st.commit(k->st.ctx) == 0) {
                char d[32];
                snprintf(d, sizeof(d), "bound on core %u", (unsigned)peer);
                if (got == 0) {
                    oc_core_loc_send_cancel(k, s.number, l.core, l.cell_id, l.tmid, OC_CORE_CANCEL_REACTIVATED, NULL, d);
                }
                oc_core_audit(k, OC_CORE_AUDIT_ACTIVATE, s.number, tmid, 0, d); /* "bound on core N": unbound here */
                oc_core_logf(k, "terminal %08x: %s, unbound here", (unsigned)tmid, d);
            }
        }
    }
    oc_sig_wipe(s.k, sizeof(s.k));
    oc_sig_wipe(s.opc, sizeof(s.opc));
}

void oc_core_visit_peer_rx(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m)
{
    if (!oc_core_peer_mob_allowed(k, core_id)) return; /* §4.5: the requester times out */
    oc_core_src_t src = { core_id, 0, 0 };
    switch (m->type) {
    case OC_OCSS_TMID_BOUND: on_bound(k, core_id, m->u.tmid_bound.tmid); break;
    case OC_OCSS_ACT_RELAY:
        src.cell = m->u.act_relay.cell;
        src.req = m->u.act_relay.req;
        oc_core_hss_act(k, &src, m->u.act_relay.tmid, m->u.act_relay.token_id, m->u.act_relay.pkt, m->u.act_relay.tag);
        break;
    case OC_OCSS_AV_RELAY:
        src.cell = m->u.av_relay.cell;
        src.req = m->u.av_relay.req;
        oc_core_hss_av(k, &src, m->u.av_relay.tmid, m->u.av_relay.count, NULL, NULL);
        break;
    case OC_OCSS_RESYNC_RELAY:
        src.cell = m->u.resync_relay.cell;
        src.req = m->u.resync_relay.req;
        oc_core_hss_av(k, &src, m->u.resync_relay.tmid, 1, m->u.resync_relay.rand, m->u.resync_relay.auts);
        break;
    case OC_OCSS_LOC_UPDATE: on_peer_loc(k, core_id, m); break;
    case OC_OCSS_LOC_PURGE:
        oc_core_reg_purge(k, core_id, m->u.peer_purge.cell, m->u.peer_purge.tmid, m->u.peer_purge.number);
        break;
    case OC_OCSS_LOCATE: on_locate(k, core_id, m); break;
    case OC_OCSS_CDR: on_peer_cdr(k, core_id, m); break;
    case OC_OCSS_ACT_RES: on_act_res(k, core_id, m); break;
    case OC_OCSS_AV_RES: on_av_res(k, core_id, m); break;
    case OC_OCSS_LOC_ACK: on_loc_ack(k, core_id, m); break;
    case OC_OCSS_LOC_CANCEL: on_peer_cancel(k, core_id, m); break;
    case OC_OCSS_LOCATE_RES: {
        oc_core_relay_t *r = relay_of(k, OC_CORE_RELAY_LOCATE, core_id, m->u.locate_res.req);
        if (r == NULL || memcmp(r->number, m->u.locate_res.number, OC_SIG_NUMBER_LEN) != 0) break;
        uint16_t id = r->id;
        relay_free(r);
        oc_core_sw_located(k, id, m->u.locate_res.status, m->u.locate_res.core, m->u.locate_res.cell);
        break;
    }
    default: break;
    }
}

/* ---- calls: LOCATE, TMID_BOUND, CDR copies ---- */

uint16_t oc_core_visit_locate(oc_core_t *k, uint16_t home, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    if (!oc_core_peer_mob(k, home)) return 0;
    oc_core_relay_t *r = relay_new(k, OC_CORE_RELAY_LOCATE, home);
    if (r == NULL) return 0;
    memcpy(r->number, number, OC_SIG_NUMBER_LEN);
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_LOCATE;
    m.u.locate.req = r->id;
    memcpy(m.u.locate.number, number, OC_SIG_NUMBER_LEN);
    if (oc_core_peer_send(k, home, &m) != 0) {
        relay_free(r);
        return 0;
    }
    return r->id;
}

void oc_core_visit_bound(oc_core_t *k, uint32_t tmid)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_OCSS_TMID_BOUND;
    m.u.tmid_bound.tmid = tmid;
    for (unsigned i = 0; i < OC_CORE_PEERS; i++) {
        const oc_core_peer_t *p = &k->peers[i];
        if (p->used && p->up && p->proto >= OC_OCSS_PROTO_MOB) oc_core_peer_send(k, p->core_id, &m);
    }
}

static int peer_leg_to(const oc_core_call_t *c, uint16_t core)
{
    return (c->a.kind == OC_CORE_LEG_PEER && c->a.peer == core) || (c->b.kind == OC_CORE_LEG_PEER && c->b.peer == core);
}

void oc_core_visit_cdr(oc_core_t *k, const oc_core_call_t *c, uint8_t cause)
{
    const uint8_t *party[2] = { c->caller, c->called };
    uint16_t sent = 0;
    for (unsigned i = 0; i < 2; i++) {
        const oc_core_block_t *b = oc_core_route_find(&k->route, party[i]);
        if (b == NULL || oc_core_route_home(&k->route, b) || b->home_core == sent) continue;
        if (peer_leg_to(c, b->home_core) || !oc_core_peer_mob(k, b->home_core)) continue; /* it saw the call, or can't hear */
        if (oc_core_number_service(k, party[i])) continue;
        oc_core_msg_t m;
        memset(&m, 0, sizeof(m));
        m.type = OC_OCSS_CDR;
        memcpy(m.u.cdr.caller, c->caller, OC_SIG_NUMBER_LEN);
        memcpy(m.u.cdr.called, c->called, OC_SIG_NUMBER_LEN);
        m.u.cdr.setup = c->setup;
        m.u.cdr.answer = c->answer;
        m.u.cdr.end = oc_core_unix(k);
        m.u.cdr.cause = cause;
        if (oc_core_peer_send(k, b->home_core, &m) != 0) {
            oc_core_logf(k, "peer %u: CDR copy not sent", (unsigned)b->home_core);
        }
        sent = b->home_core;
    }
}

/* ---- timers ---- */

void oc_core_visit_tick(oc_core_t *k)
{
    for (unsigned i = 0; i < OC_CORE_RELAYS; i++) {
        oc_core_relay_t *r = &k->relays[i];
        if (!r->used || k->now < r->due) continue;
        uint8_t kind = r->kind;
        uint16_t id = r->id;
        if (kind == OC_CORE_RELAY_AV) av_to_cell(k, r, NULL, OC_CORE_AV_UNAVAILABLE); /* the terminal retries */
        oc_core_logf(k, "relay %u (kind %u) to core %u: no answer in 3 s", (unsigned)id, (unsigned)kind,
                     (unsigned)r->peer);
        relay_free(r);
        if (kind == OC_CORE_RELAY_LOCATE) oc_core_sw_located(k, id, OC_OCSS_LOC_UNAVAILABLE, 0, 0);
    }
}

uint64_t oc_core_visit_due(const oc_core_t *k)
{
    uint64_t due = UINT64_MAX;
    for (unsigned i = 0; i < OC_CORE_RELAYS; i++) {
        if (k->relays[i].used && k->relays[i].due < due) due = k->relays[i].due;
    }
    return due;
}
