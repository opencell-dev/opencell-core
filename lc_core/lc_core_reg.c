/* The location registry (network-core spec §7.7-7.8): number -> (cell,
 * TMID, expiry, SQN), moved only by a LOC_UPDATE that proves itself with the
 * RES of a vector issued to that very cell (§8 "Location claims"; the cell
 * only has HXRES, so the RES must come from the terminal, §19.1), and never
 * back to an older claim from another cell (§19.2). */
#include "lc_core_int.h"

#include <stdio.h>
#include <string.h>

#include "lc_sig_keys.h"

/* A cell without a link purges on its new boot, or claims the number again
 * and is refused. 0, or -1 (lc_core_send: the cell has no link). */
static int cancel(lc_core_t *k, uint32_t cell, uint32_t tmid, uint8_t cause)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_CANCEL;
    m.u.loc_cancel.tmid = tmid;
    m.u.loc_cancel.cause = cause;
    return lc_core_send(k, cell, &m);
}

int lc_core_loc_live(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out)
{
    if (k->st.loc_get(k->st.ctx, number, out) != 0) return -1;
    if (out->expires > lc_core_unix(k)) return 0;
    k->st.loc_del(k->st.ctx, number);
    return -1;
}

void lc_core_loc_send_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t cell_id, uint32_t tmid,
                             uint8_t cause)
{
    char d[48];
    if (cancel(k, cell_id, tmid, cause) != 0) {
        lc_core_logf(k, "cell %u: LOC_CANCEL send failed", (unsigned)cell_id);
    }
    snprintf(d, sizeof(d), "cause %u", cause);
    lc_core_audit(k, LC_CORE_AUDIT_LOC_CANCEL, number, tmid, cell_id, d);
}

void lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause)
{
    lc_core_loc_t l;
    if (k->st.loc_get(k->st.ctx, number, &l) != 0) return;
    if (k->st.loc_del(k->st.ctx, number) != 0) {
        lc_core_logf(k, "cell %u: LOC_CANCEL: location delete failed", (unsigned)l.cell_id);
        return; /* the location is still there: nothing was actually cancelled */
    }
    lc_core_loc_send_cancel(k, number, l.cell_id, l.tmid, cause);
}

static void on_loc_update(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    const uint8_t *num = m->u.loc_update.number;
    uint32_t tmid = m->u.loc_update.tmid;
    lc_core_av_issued_t a;
    lc_core_sub_t s;
    lc_core_loc_t old, l;
    lc_core_netkey_t key;
    if (k->st.av_get(k->st.ctx, num, m->u.loc_update.rand, &a) != 0 || a.cell_id != cell ||
        !lc_sig_ct_equal(m->u.loc_update.res, a.xres, 8)) {
        lc_core_audit(k, LC_CORE_AUDIT_AUTH_FAIL, num, tmid, cell, "LOC_UPDATE: no vector of this cell's matches");
        lc_core_logf(k, "cell %u: location claim for %08x refused", (unsigned)cell, (unsigned)tmid);
        lc_sig_wipe(a.xres, sizeof(a.xres)); /* another claim's XRES, maybe: not the claimant's to learn */
        return;
    }
    int known = k->st.sub_get(k->st.ctx, num, &s) == 0;
    lc_sig_wipe(s.k, sizeof(s.k));
    lc_sig_wipe(s.opc, sizeof(s.opc));
    if (!known || !s.activated || s.tmid != tmid || s.state != LC_CORE_SUB_ACTIVE) {
        /* a proven registration the core has since cancelled (disabled
         * while the cell was cut off): the cell drops it now. s.tmid != tmid
         * catches a claim for a terminal the number is no longer bound to
         * (re-activation also deletes the old binding's vectors, §19.3). */
        int off = known && s.state == LC_CORE_SUB_DISABLED;
        lc_core_loc_send_cancel(k, num, cell, tmid, off ? LC_CORE_CANCEL_DISABLED : LC_CORE_CANCEL_REACTIVATED);
        return;
    }
    int had = k->st.loc_get(k->st.ctx, num, &old) == 0;
    if (had && old.cell_id != cell && a.sqn < old.sqn) {
        /* §19.2: an older claim than the location's, from another cell (a
         * late §7.10 offline LOC_UPDATE, or a replay): the terminal has
         * registered elsewhere since, so the claimant drops it */
        lc_core_logf(k, "cell %u: older claim for %08x refused (SQN %llu < %llu)", (unsigned)cell, (unsigned)tmid,
                     (unsigned long long)a.sqn, (unsigned long long)old.sqn);
        lc_core_loc_send_cancel(k, num, cell, tmid, LC_CORE_CANCEL_MOVED);
        return;
    }
    int moved = had && (old.cell_id != cell || old.tmid != tmid);
    memset(&l, 0, sizeof(l));
    memcpy(l.number, num, LC_SIG_NUMBER_LEN);
    l.cell_id = cell;
    l.tmid = tmid;
    l.expires = lc_core_unix(k) + 2u * (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) == 0 ? key.period_s : 1800u);
    lc_sig_wipe(key.sk, sizeof(key.sk));
    /* the newest vector that proved it: the same cell re-sending an older
     * claim refreshes the location without lowering it */
    l.sqn = had && !moved && old.sqn > a.sqn ? old.sqn : a.sqn;
    a.confirmed = 1;
    k->st.begin(k->st.ctx);
    k->st.av_put(k->st.ctx, &a);
    k->st.loc_put(k->st.ctx, &l);
    if (k->st.commit(k->st.ctx) != 0) {
        lc_core_logf(k, "location of %08x: store FAILED", (unsigned)tmid);
        return;
    }
    if (moved) lc_core_loc_send_cancel(k, num, old.cell_id, old.tmid, LC_CORE_CANCEL_MOVED); /* §7.8 */
    lc_core_audit(k, LC_CORE_AUDIT_REGISTER, num, tmid, cell, NULL);
}

/* Not wrapped in begin/commit: one write, already durable on its own
 * (lc_core_store.h). loc_del's result is checked: a genuine failure (not
 * "nothing to delete", since loc_get above just found it) is logged rather
 * than silently believed. */
static void on_loc_purge(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    lc_core_loc_t l;
    if (k->st.loc_get(k->st.ctx, m->u.loc_purge.number, &l) == 0 && l.cell_id == cell &&
        l.tmid == m->u.loc_purge.tmid) {
        if (k->st.loc_del(k->st.ctx, m->u.loc_purge.number) != 0) {
            lc_core_logf(k, "cell %u: LOC_PURGE: location delete failed", (unsigned)cell);
        }
    }
}

void lc_core_reg_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    if (m->type == LC_CORE_LOC_UPDATE) on_loc_update(k, cell_id, m);
    if (m->type == LC_CORE_LOC_PURGE) on_loc_purge(k, cell_id, m);
}

void lc_core_reg_tick(lc_core_t *k)
{
    uint32_t now = lc_core_unix(k);
    if (now > 86400u) k->st.av_prune(k->st.ctx, now - 86400u);
}
