/* The location registry (network-core spec §7.7-7.8): number -> (cell,
 * TMID, expiry), moved only by a LOC_UPDATE that proves itself with the RES
 * of a vector issued to that very cell (§8 "Location claims"). */
#include "lc_core_int.h"

#include <stdio.h>
#include <string.h>

#include "lc_sig_keys.h"

/* A cell without a link purges on its new boot, or claims the number again
 * and is refused. */
static void cancel(lc_core_t *k, uint32_t cell, uint32_t tmid, uint8_t cause)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_CANCEL;
    m.u.loc_cancel.tmid = tmid;
    m.u.loc_cancel.cause = cause;
    lc_core_send(k, cell, &m);
}

int lc_core_loc_live(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out)
{
    if (k->st.loc_get(k->st.ctx, number, out) != 0) return -1;
    if (out->expires > lc_core_unix(k)) return 0;
    k->st.loc_del(k->st.ctx, number);
    return -1;
}

void lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause)
{
    lc_core_loc_t l;
    if (k->st.loc_get(k->st.ctx, number, &l) != 0) return;
    cancel(k, l.cell_id, l.tmid, cause);
    k->st.loc_del(k->st.ctx, number);
    char d[48];
    snprintf(d, sizeof(d), "cause %u", cause);
    lc_core_audit(k, LC_CORE_AUDIT_LOC_CANCEL, number, l.tmid, l.cell_id, d);
}
