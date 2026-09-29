/* The location registry (network-core spec §7.7-7.8): number -> (cell,
 * TMID, expiry, SQN), moved only by a LOC_UPDATE that proves itself with the
 * RES of a vector issued to that very cell (§8 "Location claims"; the cell
 * only has HXRES, so the RES must come from the terminal, §19.1), and never
 * back to an older claim from another cell (§19.2). */
#include "oc_core_int.h"

#include <stdio.h>
#include <string.h>

#include "oc_sig_keys.h"

/* A cell without a link purges on its new boot, or claims the number again
 * and is refused. 0, or -1 (oc_core_send: the cell has no link). */
static int cancel(oc_core_t *k, uint32_t cell, uint32_t tmid, uint8_t cause, const uint8_t *rand)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_LOC_CANCEL;
    m.u.loc_cancel.tmid = tmid;
    m.u.loc_cancel.cause = cause;
    if (rand != NULL) memcpy(m.u.loc_cancel.rand, rand, 16);
    return oc_core_send(k, cell, &m);
}

int oc_core_loc_live(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_loc_t *out)
{
    int r = k->st.loc_get(k->st.ctx, number, out);
    if (r != 0) return r; /* none, or the store failed: not live either way */
    if (out->expires > oc_core_unix(k)) return 0;
    k->st.loc_del(k->st.ctx, number);
    return OC_CORE_STORE_NONE;
}

void oc_core_loc_send_cancel(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], uint32_t cell_id, uint32_t tmid,
                             uint8_t cause, const uint8_t *rand, const char *why)
{
    char d[48];
    if (cancel(k, cell_id, tmid, cause, rand) != 0) {
        oc_core_logf(k, "cell %u: LOC_CANCEL send failed", (unsigned)cell_id);
    }
    if (why != NULL) {
        snprintf(d, sizeof(d), "%s, cause %u", why, cause);
    } else {
        snprintf(d, sizeof(d), "cause %u", cause);
    }
    oc_core_audit(k, OC_CORE_AUDIT_LOC_CANCEL, number, tmid, cell_id, d);
}

/* §7.7-7.8, §8, §19. Single exit: every path wipes what it read. */
static void on_loc_update(oc_core_t *k, uint32_t cell, const oc_core_msg_t *m)
{
    const uint8_t *num = m->u.loc_update.number;
    uint32_t tmid = m->u.loc_update.tmid;
    oc_core_av_issued_t a;
    oc_core_sub_t s;
    oc_core_loc_t old, l;
    oc_core_netkey_t key;
    uint64_t floor = 0, top;
    memset(&a, 0, sizeof(a));
    memset(&s, 0, sizeof(s));
    memset(&key, 0, sizeof(key));
    int proven = k->st.av_get(k->st.ctx, num, m->u.loc_update.rand, &a) == 0 && a.cell_id == cell &&
                 oc_sig_ct_equal(m->u.loc_update.res, a.xres, 8);
    int got = k->st.sub_get(k->st.ctx, num, &s);
    if (got == OC_CORE_STORE_FAILED) { /* fail closed (oc_core_store.h): no cancel, no location */
        oc_core_logf(k, "cell %u: location claim for %08x: subscriber read FAILED", (unsigned)cell, (unsigned)tmid);
        goto done;
    }
    int known = got == 0;
    if ((known && (!s.activated || s.tmid != tmid || s.state != OC_CORE_SUB_ACTIVE)) || (proven && !known)) {
        /* a claim for a binding the core has since cancelled (re-activated
         * or disabled while the cell was cut off): the cell drops it now.
         * Proven or not - re-activation deleted the old binding's vectors
         * (§19.3) - since the cancel only reaches the claimant, about its
         * own TMID. A stale claim, audited as the LOC_CANCEL, not AUTH_FAIL;
         * an unproven one apart from a real re-activation's or disabling's
         * cancel ("unproven stale claim"): a cell cut off through the
         * re-activation sends one, and so does a cell probing TMIDs. */
        int off = known && s.state == OC_CORE_SUB_DISABLED;
        oc_core_loc_send_cancel(k, num, cell, tmid, off ? OC_CORE_CANCEL_DISABLED : OC_CORE_CANCEL_REACTIVATED, NULL,
                                proven ? NULL : "unproven stale claim");
        goto done;
    }
    if (!proven) {
        oc_core_audit(k, OC_CORE_AUDIT_AUTH_FAIL, num, tmid, cell, "LOC_UPDATE: no vector of this cell's matches");
        oc_core_logf(k, "cell %u: location claim for %08x refused", (unsigned)cell, (unsigned)tmid);
        goto done;
    }
    got = k->st.loc_get(k->st.ctx, num, &old);
    if (got == OC_CORE_STORE_FAILED) { /* the floor below can't be skipped for it: refused */
        oc_core_logf(k, "cell %u: location claim for %08x: location read FAILED", (unsigned)cell, (unsigned)tmid);
        goto done;
    }
    int had = got == 0;
    if (!had || old.cell_id != cell) {
        /* §19.2: not older than the location, nor than any vector another
         * cell has proved (those rows outlive a purged or expired location
         * as long as this claim's vector can be replayed) */
        /* the location's own SQN is a floor here too, deliberately, next to
         * the confirmed-av_issued floor below: defence in depth against a
         * stale replay the other floor alone might miss (e.g. no confirmed
         * row survives a purge) - do not "simplify" this away. */
        if (had) floor = old.sqn;
        got = k->st.av_newest_confirmed(k->st.ctx, num, cell, &top);
        if (got == OC_CORE_STORE_FAILED) { /* no floor known: refused, not waved through */
            oc_core_logf(k, "cell %u: location claim for %08x: vector read FAILED", (unsigned)cell,
                         (unsigned)tmid);
            goto done;
        }
        if (got == 0 && top > floor) floor = top;
        if (a.sqn < floor) {
            /* a late §7.10 offline LOC_UPDATE, or a replay: the terminal has
             * registered elsewhere since, so the claimant drops it */
            oc_core_logf(k, "cell %u: older claim for %08x refused (SQN %llu < %llu)", (unsigned)cell,
                         (unsigned)tmid, (unsigned long long)a.sqn, (unsigned long long)floor);
            /* the claim's own RAND: a newer registration there stays. Its
             * own audit detail, apart from a normal move's cancel, so an
             * operator can alert on replays */
            oc_core_loc_send_cancel(k, num, cell, tmid, OC_CORE_CANCEL_MOVED, m->u.loc_update.rand,
                                    "older claim refused");
            goto done;
        }
    }
    int moved = had && (old.cell_id != cell || old.tmid != tmid);
    memset(&l, 0, sizeof(l));
    memcpy(l.number, num, OC_SIG_NUMBER_LEN);
    l.cell_id = cell;
    l.tmid = tmid;
    l.expires = oc_core_unix(k) + 2u * (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) == 0 ? key.period_s : 1800u);
    /* the newest vector that proved it: the same cell re-sending an older
     * claim refreshes the location without lowering it */
    int keep = had && !moved && old.sqn > a.sqn;
    l.sqn = keep ? old.sqn : a.sqn;
    memcpy(l.rand, keep ? old.rand : m->u.loc_update.rand, 16);
    a.confirmed = 1;
    if (oc_core_begin(k) != 0) goto done;
    k->st.av_put(k->st.ctx, &a);
    k->st.loc_put(k->st.ctx, &l);
    if (k->st.commit(k->st.ctx) != 0) {
        oc_core_logf(k, "location of %08x: store FAILED", (unsigned)tmid);
        goto done;
    }
    /* §7.8, naming the registration it cancels: if the terminal has since
     * registered there again (a LOC_UPDATE still on its way), that one stays */
    if (moved) oc_core_loc_send_cancel(k, num, old.cell_id, old.tmid, OC_CORE_CANCEL_MOVED, old.rand, NULL);
    oc_core_audit(k, OC_CORE_AUDIT_REGISTER, num, tmid, cell, NULL);
done:
    oc_sig_wipe(a.xres, sizeof(a.xres));
    oc_sig_wipe(s.k, sizeof(s.k));
    oc_sig_wipe(s.opc, sizeof(s.opc));
    oc_sig_wipe(key.sk, sizeof(key.sk));
}

/* Not wrapped in begin/commit: one write, already durable on its own
 * (oc_core_store.h). loc_del's result is checked: a genuine failure (not
 * "nothing to delete", since loc_get above just found it) is logged rather
 * than silently believed. */
static void on_loc_purge(oc_core_t *k, uint32_t cell, const oc_core_msg_t *m)
{
    oc_core_loc_t l;
    if (k->st.loc_get(k->st.ctx, m->u.loc_purge.number, &l) == 0 && l.cell_id == cell &&
        l.tmid == m->u.loc_purge.tmid) {
        if (k->st.loc_del(k->st.ctx, m->u.loc_purge.number) != 0) {
            oc_core_logf(k, "cell %u: LOC_PURGE: location delete failed", (unsigned)cell);
        }
    }
}

void oc_core_reg_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m)
{
    if (m->type == OC_CORE_LOC_UPDATE) on_loc_update(k, cell_id, m);
    if (m->type == OC_CORE_LOC_PURGE) on_loc_purge(k, cell_id, m);
}

void oc_core_reg_tick(oc_core_t *k)
{
    uint32_t now = oc_core_unix(k);
    if (now > 86400u) k->st.av_prune(k->st.ctx, now - 86400u);
}
