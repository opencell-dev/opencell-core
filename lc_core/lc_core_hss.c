/* The HSS/AuC (network-core spec §4.2, §7.1-7.2): subscribers and tokens,
 * activation, vectors and resync. Every change is committed before the
 * answer that depends on it leaves: a vector's SQN is on disk before the
 * terminal can see it. */
#include "lc_core_int.h"

#include <stdio.h>
#include <string.h>

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
    if (had_loc) k->st.loc_del(k->st.ctx, number); /* atomic with disabling: a failed commit undoes both */
    if (k->st.commit(k->st.ctx) != 0) return -1;
    if (had_loc) lc_core_loc_send_cancel(k, number, l.cell_id, l.tmid, LC_CORE_CANCEL_DISABLED);
    lc_core_audit(k, LC_CORE_AUDIT_SUB_DISABLE, number, s.tmid, 0, NULL);
    return 0;
}
