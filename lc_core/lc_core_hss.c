/* The HSS/AuC (network-core spec §4.2, §7.1-7.2): subscribers and tokens,
 * activation, vectors and resync. Every change is committed before the
 * answer that depends on it leaves: a vector's SQN is on disk before the
 * terminal can see it. */
#include "lc_core_int.h"

#include <stdio.h>
#include <string.h>

#include "lc_sig_hss.h"
#include "lc_sig_keys.h" /* lc_sig_wipe */

static int home_number(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    return lc_core_route_home(&k->route, lc_core_route_find(&k->route, number));
}

int lc_core_sub_add(lc_core_t *k, const uint8_t *number, uint8_t out[LC_SIG_NUMBER_LEN])
{
    lc_core_sub_t s;
    uint8_t n[LC_SIG_NUMBER_LEN];
    if (number != NULL) {
        if (!lc_sig_number_valid(number) || lc_core_number_reserved(number) || !home_number(k, number) ||
            k->st.sub_get(k->st.ctx, number, &s) == 0) {
            return -1;
        }
        memcpy(n, number, LC_SIG_NUMBER_LEN);
    } else {
        const lc_core_block_t *b = NULL;
        for (unsigned i = 0; i < k->route.n && b == NULL; i++) {
            if (lc_core_route_home(&k->route, &k->route.b[i]) && k->route.b[i].prefix[3] == '1') b = &k->route.b[i];
        }
        int found = 0;
        for (int tries = 0; b != NULL && tries < 64 && !found; tries++) {
            uint8_t r[8];
            k->io.random(k->io.ctx, r, sizeof(r));
            if (lc_core_number_pick(b, r, n) != 0) return -1;
            /* a pick can land in a longer block inside this one: not ours to assign */
            found = lc_core_route_find(&k->route, n) == b && k->st.sub_get(k->st.ctx, n, &s) != 0;
        }
        if (!found) return -1;
    }
    memset(&s, 0, sizeof(s));
    memcpy(s.number, n, LC_SIG_NUMBER_LEN);
    s.state = LC_CORE_SUB_ACTIVE;
    s.created = s.updated = lc_core_unix(k);
    if (k->st.sub_put(k->st.ctx, &s) != 0) return -1;
    memcpy(out, n, LC_SIG_NUMBER_LEN);
    return 0;
}

int lc_core_token_issue(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t valid_s, lc_sig_qr_t *qr)
{
    lc_core_sub_t s;
    lc_core_netkey_t key;
    lc_core_token_t t, other;
    const lc_core_block_t *b = lc_core_route_find(&k->route, number);
    if (!lc_core_route_home(&k->route, b) || k->st.sub_get(k->st.ctx, number, &s) != 0 ||
        s.state != LC_CORE_SUB_ACTIVE || k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) != 0) {
        return -1;
    }
    memset(&t, 0, sizeof(t));
    int tries = 0;
    do {
        uint8_t r6[6];
        if (++tries > 8) return -1;
        k->io.random(k->io.ctx, r6, sizeof(r6));
        lc_core_token_id(b->block_idx, r6, t.token_id);
    } while (k->st.token_get(k->st.ctx, t.token_id, &other) == 0);
    memcpy(t.number, number, LC_SIG_NUMBER_LEN);
    k->io.random(k->io.ctx, t.secret, sizeof(t.secret));
    t.expiry = lc_core_unix(k) + valid_s;
    k->st.begin(k->st.ctx);
    k->st.token_void(k->st.ctx, number); /* at most one unused token per number */
    k->st.token_put(k->st.ctx, &t);
    if (k->st.commit(k->st.ctx) != 0) return -1;
    lc_core_audit(k, LC_CORE_AUDIT_TOKEN_ISSUE, number, 0, 0, NULL);
    memset(qr, 0, sizeof(*qr));
    qr->key_id = k->cfg.key_id;
    memcpy(qr->pkn, key.pk, 32);
    memcpy(qr->token_id, t.token_id, 8);
    memcpy(qr->token_secret, t.secret, 16);
    memcpy(qr->number, number, LC_SIG_NUMBER_LEN);
    qr->expiry = t.expiry;
    return 0;
}

int lc_core_sub_disable(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint64_t now_us)
{
    lc_core_sub_t s;
    lc_core_loc_t l;
    int had_loc;
    k->now = now_us;
    if (k->st.sub_get(k->st.ctx, number, &s) != 0) return -1;
    had_loc = k->st.loc_get(k->st.ctx, number, &l) == 0;
    s.state = LC_CORE_SUB_DISABLED;
    s.updated = lc_core_unix(k);
    k->st.begin(k->st.ctx);
    k->st.sub_put(k->st.ctx, &s);
    k->st.token_void(k->st.ctx, number);
    /* atomic with disabling: a genuine delete failure (not "nothing to
     * delete", since loc_get above just found it) dooms the commit below;
     * logged here too, for a diagnosis that does not depend on that. */
    if (had_loc && k->st.loc_del(k->st.ctx, number) != 0) {
        lc_core_logf(k, "sub_disable %08x: location delete failed", (unsigned)l.tmid);
    }
    if (k->st.commit(k->st.ctx) != 0) return -1;
    if (had_loc) lc_core_loc_send_cancel(k, number, l.cell_id, l.tmid, LC_CORE_CANCEL_DISABLED);
    lc_core_audit(k, LC_CORE_AUDIT_SUB_DISABLE, number, s.tmid, 0, NULL);
    return 0;
}

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, LC_SIG_NUMBER_LEN) == 0; }

/* §7.1: the plan-5 checks, then bind, all in one commit (the old locations'
 * loc_del inside it too, as lc_core_sub_disable does); then the old
 * terminals are cut off (LOC_CANCEL after the commit, so a cell drops its
 * old session once the bind that replaces it is durable, and never on a
 * bind that the store then failed to keep). Single exit: every path wipes
 * the key material it touched. */
static void on_act_fwd(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    static const uint8_t none[LC_SIG_NUMBER_LEN] = { 0 };
    const uint8_t *tid = m->u.act_fwd.token_id;
    uint32_t tmid = m->u.act_fwd.tmid;
    lc_core_token_t tok;
    lc_core_sub_t sub, other;
    lc_core_netkey_t key;
    lc_sig_act_token_t t;
    lc_core_msg_t r;
    lc_core_loc_t loc_self, loc_other;
    uint8_t kk[16], opc[16];
    int had_loc_self = 0, had_loc_other = 0;
    memset(&tok, 0, sizeof(tok));
    memset(&sub, 0, sizeof(sub));
    memset(&other, 0, sizeof(other));
    memset(&key, 0, sizeof(key));
    memset(&t, 0, sizeof(t));
    memset(&r, 0, sizeof(r));
    memset(&loc_self, 0, sizeof(loc_self));
    memset(&loc_other, 0, sizeof(loc_other));
    memset(kk, 0, sizeof(kk));
    memset(opc, 0, sizeof(opc));
    if (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) != 0) {
        lc_core_logf(k, "activation: no network key %u", k->cfg.key_id);
        goto done;
    }
    /* the token id's block says which core holds it (§14.3): one core, so
     * a token of a block this core isn't home for is unknown here */
    int known = lc_core_route_home(&k->route, lc_core_route_block(&k->route, lc_core_token_block(tid))) &&
                k->st.token_get(k->st.ctx, tid, &tok) == 0 && k->st.sub_get(k->st.ctx, tok.number, &sub) == 0 &&
                sub.state == LC_CORE_SUB_ACTIVE;
    if (known) {
        t.known = 1;
        t.used = tok.used_at != 0;
        t.expiry = tok.expiry;
        memcpy(t.secret, tok.secret, 16);
        t.bound_tmid = sub.activated ? sub.tmid : 0;
        memcpy(t.bound_k, sub.k, 16);
    }
    r.type = LC_CORE_ACT_RES;
    r.u.act_res.req = m->u.act_fwd.req;
    r.u.act_res.tmid = tmid;
    int res = lc_sig_act_answer(&t, key.sk, lc_core_unix(k), tmid, tid, m->u.act_fwd.pkt, m->u.act_fwd.tag,
                                known ? sub.number : none, &r.u.act_res.msg, kk, opc);
    if (res == LC_SIG_ACT_REFUSED) {
        char d[48];
        snprintf(d, sizeof(d), "reason %u", r.u.act_res.msg.u.act_nak.reason);
        lc_core_audit(k, LC_CORE_AUDIT_ACT_FAIL, known ? sub.number : NULL, tmid, cell, d);
    } else if (res == LC_SIG_ACT_FRESH) {
        int had_other = k->st.sub_by_tmid(k->st.ctx, tmid, &other) == 0 && !num_eq(other.number, sub.number);
        had_loc_self = k->st.loc_get(k->st.ctx, sub.number, &loc_self) == 0;
        had_loc_other = had_other && k->st.loc_get(k->st.ctx, other.number, &loc_other) == 0;
        k->st.begin(k->st.ctx);
        if (had_other) { /* the terminal's previous subscriber loses it */
            other.activated = 0;
            other.tmid = 0;
            other.updated = lc_core_unix(k);
            k->st.sub_put(k->st.ctx, &other);
            /* a genuine delete failure (not "nothing to delete": loc_get
             * above just found it) dooms the commit below; logged here too. */
            if (had_loc_other && k->st.loc_del(k->st.ctx, other.number) != 0) {
                lc_core_logf(k, "activation of %08x: other number's location delete failed", (unsigned)tmid);
            }
        }
        memcpy(sub.k, kk, 16);
        memcpy(sub.opc, opc, 16);
        sub.sqn = 0;
        sub.tmid = tmid;
        sub.activated = 1;
        sub.updated = lc_core_unix(k);
        k->st.sub_put(k->st.ctx, &sub);
        /* wherever it was registered: atomic with the bind */
        if (had_loc_self && k->st.loc_del(k->st.ctx, sub.number) != 0) {
            lc_core_logf(k, "activation of %08x: location delete failed", (unsigned)tmid);
        }
        /* §19.3: vectors of the old binding (old K) must not prove a
         * location for the new one; deleting none is not a failure */
        k->st.av_del_number(k->st.ctx, sub.number);
        tok.used_at = lc_core_unix(k);
        tok.used_by_tmid = tmid;
        k->st.token_put(k->st.ctx, &tok);
        if (k->st.commit(k->st.ctx) != 0) {
            lc_core_logf(k, "activation of %08x: store FAILED, no answer", (unsigned)tmid);
            goto done; /* the terminal retries; no LOC_CANCEL either: nothing actually changed */
        }
        if (had_loc_other) {
            lc_core_loc_send_cancel(k, other.number, loc_other.cell_id, loc_other.tmid, LC_CORE_CANCEL_REACTIVATED);
        }
        if (had_loc_self) {
            lc_core_loc_send_cancel(k, sub.number, loc_self.cell_id, loc_self.tmid, LC_CORE_CANCEL_REACTIVATED);
        }
        lc_core_audit(k, LC_CORE_AUDIT_ACTIVATE, sub.number, tmid, cell, NULL);
    }
    lc_core_send(k, cell, &r);
done:
    lc_sig_wipe(kk, sizeof(kk));
    lc_sig_wipe(opc, sizeof(opc));
    lc_sig_wipe(key.sk, sizeof(key.sk));
    lc_sig_wipe(t.secret, sizeof(t.secret));
    lc_sig_wipe(t.bound_k, sizeof(t.bound_k));
    lc_sig_wipe(tok.secret, sizeof(tok.secret));
    lc_sig_wipe(sub.k, sizeof(sub.k));
    lc_sig_wipe(sub.opc, sizeof(sub.opc));
    lc_sig_wipe(other.k, sizeof(other.k));
    lc_sig_wipe(other.opc, sizeof(other.opc));
}

/* 0 (and the subscriber) when tmid may have vectors, else the status. */
static uint8_t av_status(lc_core_t *k, uint32_t tmid, lc_core_sub_t *sub)
{
    if (k->st.sub_by_tmid(k->st.ctx, tmid, sub) != 0) return LC_CORE_AV_NOT_ACTIVATED;
    if (sub->state != LC_CORE_SUB_ACTIVE) return LC_CORE_AV_DISABLED;
    if (!home_number(k, sub->number)) return LC_CORE_AV_UNAVAILABLE;
    return LC_CORE_AV_OK;
}

/* §7.2: count vectors, computed first (so a crypto failure never touches
 * the store) and only then committed together (SQN and every av_issued row)
 * before AV_RES leaves: the store contract makes a failed put fail the
 * whole commit, so a full AV table answers UNAVAILABLE instead of sending a
 * vector no av_issued row backs. XRES stays in av_issued; the cell gets its
 * HXRES (§19.1), so only the terminal's own RES proves a location. For
 * RESYNC, SQN from AUTS first (TS 33.102 §6.3.5): the RAND must be one this
 * core issued to the number, and SQN_HE
 * only ever moves forward, never back to a replayed (RAND, AUTS). Single
 * exit: every path wipes the key material it touched. */
static void answer_av(lc_core_t *k, uint32_t cell, uint16_t req, uint32_t tmid, unsigned count, const uint8_t *rand,
                      const uint8_t *auts)
{
    lc_core_msg_t r;
    lc_core_sub_t sub;
    lc_core_av_issued_t iss[LC_CORE_AV_MAX];
    lc_sig_av_t full;
    uint8_t ms[6];
    memset(&r, 0, sizeof(r));
    memset(&sub, 0, sizeof(sub));
    memset(iss, 0, sizeof(iss));
    memset(&full, 0, sizeof(full));
    memset(ms, 0, sizeof(ms));
    r.type = LC_CORE_AV_RES;
    r.u.av_res.req = req;
    r.u.av_res.tmid = tmid;
    uint8_t st = av_status(k, tmid, &sub);
    int resynced = 0;
    if (st == LC_CORE_AV_OK && auts != NULL) {
        lc_core_av_issued_t seen;
        if (k->st.av_get(k->st.ctx, sub.number, rand, &seen) != 0) {
            st = LC_CORE_AV_AUTH_FAILED;
            lc_core_audit(k, LC_CORE_AUDIT_AUTH_FAIL, sub.number, tmid, cell, "RAND not issued to this number");
        } else if (lc_sig_av_auts(sub.k, sub.opc, rand, auts, ms) != 0) {
            st = LC_CORE_AV_AUTH_FAILED;
            lc_core_audit(k, LC_CORE_AUDIT_AUTH_FAIL, sub.number, tmid, cell, "AUTS did not verify");
        } else {
            /* TS 33.102 §6.3.5 step 2: SQN_HE only ever moves forward; a
             * replayed (RAND, AUTS) whose SQN_MS is not ahead of what the
             * core already holds changes nothing (no rollback). */
            uint64_t sqn_ms = lc_sig_sqn_get(ms);
            if (sqn_ms > sub.sqn) sub.sqn = sqn_ms;
            resynced = 1;
        }
    }
    if (st == LC_CORE_AV_OK) {
        uint64_t sqn = sub.sqn;
        int ok = 1;
        count = count < 1 ? 1 : count > LC_CORE_AV_MAX ? LC_CORE_AV_MAX : count;
        for (unsigned i = 0; i < count; i++) {
            uint8_t sqn6[6], rnd[16];
            sqn++;
            lc_sig_sqn_put(sqn6, sqn);
            k->io.random(k->io.ctx, rnd, sizeof(rnd));
            if (lc_sig_av_make(sub.k, sub.opc, sqn6, rnd, &full) != 0 ||
                lc_sig_av_for_cell(&full, &r.u.av_res.av[i]) != 0) {
                ok = 0;
                break;
            }
            memcpy(iss[i].number, sub.number, LC_SIG_NUMBER_LEN);
            memcpy(iss[i].rand, rnd, 16);
            memcpy(iss[i].xres, full.xres, 8);
            lc_sig_wipe(&full, sizeof(full));
            iss[i].sqn = sqn;
            iss[i].cell_id = cell;
            iss[i].issued = lc_core_unix(k);
        }
        if (!ok) {
            lc_core_logf(k, "vectors for %08x: lc_sig_av_make failed", (unsigned)tmid);
            st = LC_CORE_AV_UNAVAILABLE;
            memset(r.u.av_res.av, 0, sizeof(r.u.av_res.av));
        } else {
            sub.sqn = sqn;
            sub.updated = lc_core_unix(k);
            k->st.begin(k->st.ctx);
            for (unsigned i = 0; i < count; i++) k->st.av_put(k->st.ctx, &iss[i]);
            k->st.sub_put(k->st.ctx, &sub);
            if (k->st.commit(k->st.ctx) != 0) {
                lc_core_logf(k, "vectors for %08x: store FAILED", (unsigned)tmid);
                st = LC_CORE_AV_UNAVAILABLE;
                memset(r.u.av_res.av, 0, sizeof(r.u.av_res.av));
            } else {
                memcpy(r.u.av_res.number, sub.number, LC_SIG_NUMBER_LEN);
                r.u.av_res.count = (uint8_t)count;
                if (resynced) lc_core_audit(k, LC_CORE_AUDIT_RESYNC, sub.number, tmid, cell, NULL);
            }
        }
    }
    r.u.av_res.status = st;
    lc_core_send(k, cell, &r);
    lc_sig_wipe(sub.k, sizeof(sub.k));
    lc_sig_wipe(sub.opc, sizeof(sub.opc));
    lc_sig_wipe(ms, sizeof(ms));
    lc_sig_wipe(&full, sizeof(full)); /* XRES, CK, IK of a vector cut short */
    lc_sig_wipe(iss, sizeof(iss));    /* XRES */
    for (unsigned i = 0; i < LC_CORE_AV_MAX; i++) {
        lc_sig_wipe(r.u.av_res.av[i].hxres, sizeof(r.u.av_res.av[i].hxres));
        lc_sig_wipe(r.u.av_res.av[i].ck, sizeof(r.u.av_res.av[i].ck));
        lc_sig_wipe(r.u.av_res.av[i].ik, sizeof(r.u.av_res.av[i].ik));
    }
}

void lc_core_hss_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    switch (m->type) {
    case LC_CORE_ACT_FWD:
        on_act_fwd(k, cell_id, m);
        break;
    case LC_CORE_AV_REQ:
        answer_av(k, cell_id, m->u.av_req.req, m->u.av_req.tmid, m->u.av_req.count, NULL, NULL);
        break;
    case LC_CORE_RESYNC:
        answer_av(k, cell_id, m->u.resync.req, m->u.resync.tmid, 1, m->u.resync.rand, m->u.resync.auts);
        break;
    default:
        break;
    }
}
