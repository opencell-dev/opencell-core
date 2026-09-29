/* The HSS/AuC (network-core spec §4.2, §7.1-7.2): subscribers and tokens,
 * activation, vectors and resync. Every change is committed before the
 * answer that depends on it leaves: a vector's SQN is on disk before the
 * terminal can see it. */
#include "oc_core_int.h"

#include <stdio.h>
#include <string.h>

#include "oc_sig_hss.h"
#include "oc_sig_keys.h" /* oc_sig_wipe */

static int home_number(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    return oc_core_route_home(&k->route, oc_core_route_find(&k->route, number));
}

/* Single exit: the record read to check for a duplicate (its K and OPc)
 * is wiped on every path. A number whose record the store could not read
 * is never taken for a free one (oc_core_store.h: fail closed). */
int oc_core_sub_add(oc_core_t *k, const uint8_t *number, uint8_t out[OC_SIG_NUMBER_LEN])
{
    oc_core_sub_t s;
    uint8_t n[OC_SIG_NUMBER_LEN];
    int ret = -1;
    memset(&s, 0, sizeof(s));
    if (number != NULL) {
        if (!oc_sig_number_valid(number) || oc_core_number_reserved(number) || !home_number(k, number) ||
            k->st.sub_get(k->st.ctx, number, &s) != OC_CORE_STORE_NONE) {
            goto done;
        }
        memcpy(n, number, OC_SIG_NUMBER_LEN);
    } else {
        const oc_core_block_t *b = NULL;
        for (unsigned i = 0; i < k->route.n && b == NULL; i++) {
            if (oc_core_route_home(&k->route, &k->route.b[i]) && k->route.b[i].prefix[3] == '1') b = &k->route.b[i];
        }
        int found = 0;
        for (int tries = 0; b != NULL && tries < 64 && !found; tries++) {
            uint8_t r[8];
            k->io.random(k->io.ctx, r, sizeof(r));
            if (oc_core_number_pick(b, r, n) != 0) goto done;
            /* a pick can land in a longer block inside this one: not ours to assign */
            if (oc_core_route_find(&k->route, n) != b) continue;
            int got = k->st.sub_get(k->st.ctx, n, &s);
            if (got == OC_CORE_STORE_FAILED) goto done;
            found = got == OC_CORE_STORE_NONE;
        }
        if (!found) goto done;
    }
    oc_sig_wipe(&s, sizeof(s));
    memcpy(s.number, n, OC_SIG_NUMBER_LEN);
    s.state = OC_CORE_SUB_ACTIVE;
    s.created = s.updated = oc_core_unix(k);
    if (k->st.sub_put(k->st.ctx, &s) != 0) goto done;
    memcpy(out, n, OC_SIG_NUMBER_LEN);
    ret = 0;
done:
    oc_sig_wipe(s.k, sizeof(s.k));
    oc_sig_wipe(s.opc, sizeof(s.opc));
    return ret;
}

/* Single exit: the network key, the new token's secret, and whatever
 * records were read (a subscriber's K/OPc, another token's secret) are
 * wiped on every path; the QR is the only copy that leaves. */
int oc_core_token_issue(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], uint32_t valid_s, oc_sig_qr_t *qr)
{
    oc_core_sub_t s;
    oc_core_netkey_t key;
    oc_core_token_t t, other;
    int ret = -1;
    memset(&s, 0, sizeof(s));
    memset(&key, 0, sizeof(key));
    memset(&t, 0, sizeof(t));
    memset(&other, 0, sizeof(other));
    const oc_core_block_t *b = oc_core_route_find(&k->route, number);
    if (!oc_core_route_home(&k->route, b) || k->st.sub_get(k->st.ctx, number, &s) != 0 ||
        s.state != OC_CORE_SUB_ACTIVE || k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) != 0) {
        goto done;
    }
    int tries = 0, got;
    do { /* an id known to be free: one whose token could not be read is not taken */
        uint8_t r6[6];
        if (++tries > 8) goto done;
        k->io.random(k->io.ctx, r6, sizeof(r6));
        oc_core_token_id(b->block_idx, r6, t.token_id);
        got = k->st.token_get(k->st.ctx, t.token_id, &other);
        if (got == OC_CORE_STORE_FAILED) goto done;
    } while (got != OC_CORE_STORE_NONE);
    memcpy(t.number, number, OC_SIG_NUMBER_LEN);
    k->io.random(k->io.ctx, t.secret, sizeof(t.secret));
    t.expiry = oc_core_unix(k) + valid_s;
    if (oc_core_begin(k) != 0) goto done;
    k->st.token_void(k->st.ctx, number); /* at most one unused token per number */
    k->st.token_put(k->st.ctx, &t);
    if (k->st.commit(k->st.ctx) != 0) goto done;
    oc_core_audit(k, OC_CORE_AUDIT_TOKEN_ISSUE, number, 0, 0, NULL);
    memset(qr, 0, sizeof(*qr));
    qr->key_id = k->cfg.key_id;
    memcpy(qr->pkn, key.pk, 32);
    memcpy(qr->token_id, t.token_id, 8);
    memcpy(qr->token_secret, t.secret, 16);
    memcpy(qr->number, number, OC_SIG_NUMBER_LEN);
    qr->expiry = t.expiry;
    ret = 0;
done:
    oc_sig_wipe(key.sk, sizeof(key.sk));
    oc_sig_wipe(t.secret, sizeof(t.secret));
    oc_sig_wipe(other.secret, sizeof(other.secret));
    oc_sig_wipe(s.k, sizeof(s.k));
    oc_sig_wipe(s.opc, sizeof(s.opc));
    return ret;
}

/* Single exit, as above: the subscriber's K and OPc are wiped. A location
 * the store could not read refuses the disabling (fail closed): it would
 * otherwise stay behind, uncancelled. */
int oc_core_sub_disable(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], uint64_t now_us)
{
    oc_core_sub_t s;
    oc_core_loc_t l;
    int had_loc, ret = -1;
    k->now = now_us;
    memset(&s, 0, sizeof(s));
    if (k->st.sub_get(k->st.ctx, number, &s) != 0) goto done;
    int got = k->st.loc_get(k->st.ctx, number, &l);
    if (got == OC_CORE_STORE_FAILED) {
        oc_core_logf(k, "sub_disable %08x: location read FAILED", (unsigned)s.tmid);
        goto done;
    }
    had_loc = got == 0;
    s.state = OC_CORE_SUB_DISABLED;
    s.updated = oc_core_unix(k);
    if (oc_core_begin(k) != 0) goto done;
    k->st.sub_put(k->st.ctx, &s);
    k->st.token_void(k->st.ctx, number);
    /* atomic with disabling: a genuine delete failure (not "nothing to
     * delete", since loc_get above just found it) dooms the commit below;
     * logged here too, for a diagnosis that does not depend on that. */
    if (had_loc && k->st.loc_del(k->st.ctx, number) != 0) {
        oc_core_logf(k, "sub_disable %08x: location delete failed", (unsigned)l.tmid);
    }
    if (k->st.commit(k->st.ctx) != 0) goto done;
    if (had_loc) oc_core_loc_send_cancel(k, number, l.cell_id, l.tmid, OC_CORE_CANCEL_DISABLED, NULL, NULL);
    oc_core_audit(k, OC_CORE_AUDIT_SUB_DISABLE, number, s.tmid, 0, NULL);
    ret = 0;
done:
    oc_sig_wipe(s.k, sizeof(s.k));
    oc_sig_wipe(s.opc, sizeof(s.opc));
    return ret;
}

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, OC_SIG_NUMBER_LEN) == 0; }

/* §7.1: the plan-5 checks, then bind, all in one commit (the old locations'
 * loc_del inside it too, as oc_core_sub_disable does); then the old
 * terminals are cut off (LOC_CANCEL after the commit, so a cell drops its
 * old session once the bind that replaces it is durable, and never on a
 * bind that the store then failed to keep). Single exit: every path wipes
 * the key material it touched. */
static void on_act_fwd(oc_core_t *k, uint32_t cell, const oc_core_msg_t *m)
{
    static const uint8_t none[OC_SIG_NUMBER_LEN] = { 0 };
    const uint8_t *tid = m->u.act_fwd.token_id;
    uint32_t tmid = m->u.act_fwd.tmid;
    oc_core_token_t tok;
    oc_core_sub_t sub, other;
    oc_core_netkey_t key;
    oc_sig_act_token_t t;
    oc_core_msg_t r;
    oc_core_loc_t loc_self, loc_other;
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
        oc_core_logf(k, "activation: no network key %u", k->cfg.key_id);
        goto done;
    }
    /* the token id's block says which core holds it (§14.3): one core, so
     * a token of a block this core isn't home for is unknown here */
    int known = oc_core_route_home(&k->route, oc_core_route_block(&k->route, oc_core_token_block(tid)));
    if (known) {
        int got = k->st.token_get(k->st.ctx, tid, &tok);
        if (got == OC_CORE_STORE_FAILED) { /* not "unknown token": no answer, it retries */
            oc_core_logf(k, "activation of %08x: token read FAILED, no answer", (unsigned)tmid);
            goto done;
        }
        known = got == 0;
    }
    if (known) {
        int got = k->st.sub_get(k->st.ctx, tok.number, &sub);
        if (got == OC_CORE_STORE_FAILED) { /* not "unknown token" (oc_core_store.h): no answer, it retries */
            oc_core_logf(k, "activation of %08x: subscriber read FAILED, no answer", (unsigned)tmid);
            goto done;
        }
        known = got == 0 && sub.state == OC_CORE_SUB_ACTIVE;
    }
    if (known) {
        t.known = 1;
        t.used = tok.used_at != 0;
        t.expiry = tok.expiry;
        memcpy(t.secret, tok.secret, 16);
        t.bound_tmid = sub.activated ? sub.tmid : 0;
        memcpy(t.bound_k, sub.k, 16);
    }
    r.type = OC_CORE_ACT_RES;
    r.u.act_res.req = m->u.act_fwd.req;
    r.u.act_res.tmid = tmid;
    int res = oc_sig_act_answer(&t, key.sk, oc_core_unix(k), tmid, tid, m->u.act_fwd.pkt, m->u.act_fwd.tag,
                                known ? sub.number : none, &r.u.act_res.msg, kk, opc);
    if (res == OC_SIG_ACT_REFUSED) {
        char d[48];
        snprintf(d, sizeof(d), "reason %u", r.u.act_res.msg.u.act_nak.reason);
        oc_core_audit(k, OC_CORE_AUDIT_ACT_FAIL, known ? sub.number : NULL, tmid, cell, d);
    } else if (res == OC_SIG_ACT_FRESH) {
        int got_tmid = k->st.sub_by_tmid(k->st.ctx, tmid, &other);
        if (got_tmid == OC_CORE_STORE_FAILED) {
            /* fail closed (plan 8 amendment 3): the TMID may be bound to
             * another subscriber, which would keep it too */
            oc_core_logf(k, "activation of %08x: TMID read FAILED, no answer", (unsigned)tmid);
            goto done;
        }
        int had_other = got_tmid == 0 && !num_eq(other.number, sub.number);
        int got_self = k->st.loc_get(k->st.ctx, sub.number, &loc_self);
        int got_other = had_other ? k->st.loc_get(k->st.ctx, other.number, &loc_other) : OC_CORE_STORE_NONE;
        if (got_self == OC_CORE_STORE_FAILED || got_other == OC_CORE_STORE_FAILED) {
            /* fail closed (oc_core_store.h): a location that may exist
             * would outlive the binding it belongs to, uncancelled */
            oc_core_logf(k, "activation of %08x: location read FAILED, no answer", (unsigned)tmid);
            goto done;
        }
        had_loc_self = got_self == 0;
        had_loc_other = got_other == 0;
        if (oc_core_begin(k) != 0) goto done; /* no answer: the terminal retries */
        if (had_other) { /* the terminal's previous subscriber loses it */
            other.activated = 0;
            other.tmid = 0;
            other.updated = oc_core_unix(k);
            k->st.sub_put(k->st.ctx, &other);
            /* a genuine delete failure (not "nothing to delete": loc_get
             * above just found it) dooms the commit below; logged here too. */
            if (had_loc_other && k->st.loc_del(k->st.ctx, other.number) != 0) {
                oc_core_logf(k, "activation of %08x: other number's location delete failed", (unsigned)tmid);
            }
        }
        memcpy(sub.k, kk, 16);
        memcpy(sub.opc, opc, 16);
        sub.sqn = 0;
        sub.tmid = tmid;
        sub.activated = 1;
        sub.updated = oc_core_unix(k);
        k->st.sub_put(k->st.ctx, &sub);
        /* wherever it was registered: atomic with the bind */
        if (had_loc_self && k->st.loc_del(k->st.ctx, sub.number) != 0) {
            oc_core_logf(k, "activation of %08x: location delete failed", (unsigned)tmid);
        }
        /* §19.3: vectors of the old binding (old K) must not prove a
         * location for the new one; deleting none is not a failure */
        k->st.av_del_number(k->st.ctx, sub.number);
        tok.used_at = oc_core_unix(k);
        tok.used_by_tmid = tmid;
        k->st.token_put(k->st.ctx, &tok);
        if (k->st.commit(k->st.ctx) != 0) {
            oc_core_logf(k, "activation of %08x: store FAILED, no answer", (unsigned)tmid);
            goto done; /* the terminal retries; no LOC_CANCEL either: nothing actually changed */
        }
        if (had_loc_other) {
            oc_core_loc_send_cancel(k, other.number, loc_other.cell_id, loc_other.tmid, OC_CORE_CANCEL_REACTIVATED,
                                    NULL, NULL);
        }
        if (had_loc_self) {
            oc_core_loc_send_cancel(k, sub.number, loc_self.cell_id, loc_self.tmid, OC_CORE_CANCEL_REACTIVATED, NULL,
                                    NULL);
        }
        oc_core_audit(k, OC_CORE_AUDIT_ACTIVATE, sub.number, tmid, cell, NULL);
    }
    oc_core_send(k, cell, &r);
done:
    oc_sig_wipe(kk, sizeof(kk));
    oc_sig_wipe(opc, sizeof(opc));
    oc_sig_wipe(key.sk, sizeof(key.sk));
    oc_sig_wipe(t.secret, sizeof(t.secret));
    oc_sig_wipe(t.bound_k, sizeof(t.bound_k));
    oc_sig_wipe(tok.secret, sizeof(tok.secret));
    oc_sig_wipe(sub.k, sizeof(sub.k));
    oc_sig_wipe(sub.opc, sizeof(sub.opc));
    oc_sig_wipe(other.k, sizeof(other.k));
    oc_sig_wipe(other.opc, sizeof(other.opc));
}

/* 0 (and the subscriber) when tmid may have vectors, else the status. */
static uint8_t av_status(oc_core_t *k, uint32_t tmid, oc_core_sub_t *sub)
{
    int got = k->st.sub_by_tmid(k->st.ctx, tmid, sub);
    if (got == OC_CORE_STORE_FAILED) {
        oc_core_logf(k, "vectors for %08x: subscriber read FAILED", (unsigned)tmid);
        return OC_CORE_AV_UNAVAILABLE; /* a store failure, not "never activated" */
    }
    if (got != 0) return OC_CORE_AV_NOT_ACTIVATED;
    if (sub->state != OC_CORE_SUB_ACTIVE) return OC_CORE_AV_DISABLED;
    if (!home_number(k, sub->number)) return OC_CORE_AV_UNAVAILABLE;
    return OC_CORE_AV_OK;
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
static void answer_av(oc_core_t *k, uint32_t cell, uint16_t req, uint32_t tmid, unsigned count, const uint8_t *rand,
                      const uint8_t *auts)
{
    oc_core_msg_t r;
    oc_core_sub_t sub;
    oc_core_av_issued_t iss[OC_CORE_AV_MAX];
    oc_sig_av_t full;
    uint8_t ms[6];
    memset(&r, 0, sizeof(r));
    memset(&sub, 0, sizeof(sub));
    memset(iss, 0, sizeof(iss));
    memset(&full, 0, sizeof(full));
    memset(ms, 0, sizeof(ms));
    r.type = OC_CORE_AV_RES;
    r.u.av_res.req = req;
    r.u.av_res.tmid = tmid;
    uint8_t st = av_status(k, tmid, &sub);
    int resynced = 0;
    if (st == OC_CORE_AV_OK && auts != NULL) {
        oc_core_av_issued_t seen;
        memset(&seen, 0, sizeof(seen));
        int got = k->st.av_get(k->st.ctx, sub.number, rand, &seen);
        if (got == OC_CORE_STORE_FAILED) {
            oc_core_logf(k, "resync for %08x: vector read FAILED", (unsigned)tmid);
            st = OC_CORE_AV_UNAVAILABLE; /* a store failure, not a failed authentication */
        } else if (got != 0) {
            st = OC_CORE_AV_AUTH_FAILED;
            oc_core_audit(k, OC_CORE_AUDIT_AUTH_FAIL, sub.number, tmid, cell, "RAND not issued to this number");
        } else if (oc_sig_av_auts(sub.k, sub.opc, rand, auts, ms) != 0) {
            st = OC_CORE_AV_AUTH_FAILED;
            oc_core_audit(k, OC_CORE_AUDIT_AUTH_FAIL, sub.number, tmid, cell, "AUTS did not verify");
        } else {
            /* TS 33.102 §6.3.5 step 2: SQN_HE only ever moves forward; a
             * replayed (RAND, AUTS) whose SQN_MS is not ahead of what the
             * core already holds changes nothing (no rollback). */
            uint64_t sqn_ms = oc_sig_sqn_get(ms);
            if (sqn_ms > sub.sqn) sub.sqn = sqn_ms;
            resynced = 1;
        }
        oc_sig_wipe(seen.xres, sizeof(seen.xres));
    }
    if (st == OC_CORE_AV_OK) {
        uint64_t sqn = sub.sqn;
        int ok = 1;
        count = count < 1 ? 1 : count > OC_CORE_AV_MAX ? OC_CORE_AV_MAX : count;
        for (unsigned i = 0; i < count; i++) {
            uint8_t sqn6[6], rnd[16];
            sqn++;
            oc_sig_sqn_put(sqn6, sqn);
            k->io.random(k->io.ctx, rnd, sizeof(rnd));
            if (oc_sig_av_make(sub.k, sub.opc, sqn6, rnd, &full) != 0 ||
                oc_sig_av_for_cell(&full, &r.u.av_res.av[i]) != 0) {
                ok = 0;
                break;
            }
            memcpy(iss[i].number, sub.number, OC_SIG_NUMBER_LEN);
            memcpy(iss[i].rand, rnd, 16);
            memcpy(iss[i].xres, full.xres, 8);
            oc_sig_wipe(&full, sizeof(full));
            iss[i].sqn = sqn;
            iss[i].cell_id = cell;
            iss[i].issued = oc_core_unix(k);
        }
        if (!ok) {
            oc_core_logf(k, "vectors for %08x: oc_sig_av_make failed", (unsigned)tmid);
            st = OC_CORE_AV_UNAVAILABLE;
            memset(r.u.av_res.av, 0, sizeof(r.u.av_res.av));
        } else {
            sub.sqn = sqn;
            sub.updated = oc_core_unix(k);
            int began = oc_core_begin(k) == 0;
            if (began) {
                for (unsigned i = 0; i < count; i++) k->st.av_put(k->st.ctx, &iss[i]);
                k->st.sub_put(k->st.ctx, &sub);
            }
            if (!began || k->st.commit(k->st.ctx) != 0) {
                oc_core_logf(k, "vectors for %08x: store FAILED", (unsigned)tmid);
                st = OC_CORE_AV_UNAVAILABLE;
                memset(r.u.av_res.av, 0, sizeof(r.u.av_res.av));
            } else {
                memcpy(r.u.av_res.number, sub.number, OC_SIG_NUMBER_LEN);
                r.u.av_res.count = (uint8_t)count;
                if (resynced) oc_core_audit(k, OC_CORE_AUDIT_RESYNC, sub.number, tmid, cell, NULL);
            }
        }
    }
    r.u.av_res.status = st;
    oc_core_send(k, cell, &r);
    oc_sig_wipe(sub.k, sizeof(sub.k));
    oc_sig_wipe(sub.opc, sizeof(sub.opc));
    oc_sig_wipe(ms, sizeof(ms));
    oc_sig_wipe(&full, sizeof(full)); /* XRES, CK, IK of a vector cut short */
    oc_sig_wipe(iss, sizeof(iss));    /* XRES */
    for (unsigned i = 0; i < OC_CORE_AV_MAX; i++) {
        oc_sig_wipe(r.u.av_res.av[i].hxres, sizeof(r.u.av_res.av[i].hxres));
        oc_sig_wipe(r.u.av_res.av[i].ck, sizeof(r.u.av_res.av[i].ck));
        oc_sig_wipe(r.u.av_res.av[i].ik, sizeof(r.u.av_res.av[i].ik));
    }
}

void oc_core_hss_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m)
{
    switch (m->type) {
    case OC_CORE_ACT_FWD:
        on_act_fwd(k, cell_id, m);
        break;
    case OC_CORE_AV_REQ:
        answer_av(k, cell_id, m->u.av_req.req, m->u.av_req.tmid, m->u.av_req.count, NULL, NULL);
        break;
    case OC_CORE_RESYNC:
        answer_av(k, cell_id, m->u.resync.req, m->u.resync.tmid, 1, m->u.resync.rand, m->u.resync.auts);
        break;
    default:
        break;
    }
}
