/* Shared between lc_core's own files; not part of its interface. */
#ifndef LC_CORE_INT_H
#define LC_CORE_INT_H

#include "lc_core.h"

#define LC_CORE_US(s) ((uint64_t)(s) * 1000000ull)

uint32_t lc_core_unix(lc_core_t *k);
void     lc_core_logf(lc_core_t *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* To the link of cell_id: 0, or -1 when the cell has no link. */
int      lc_core_send(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);
int      lc_core_linked(const lc_core_t *k, uint32_t cell_id);
void     lc_core_audit(lc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                       const char *detail);

/* lc_core_reg.c: the number's location if it is live (an expired one is
 * deleted): 0 or -1. */
int      lc_core_loc_live(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out);
/* Tell the number's cell to drop it (LOC_CANCEL) and forget the location. */
void     lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause);
/* LOC_CANCEL and its audit for a location the caller already deleted from
 * the store, atomically with whatever else it changed (e.g. disabling): a
 * failed send is logged but still audited, since the location really is
 * gone. */
void     lc_core_loc_send_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t cell_id,
                                 uint32_t tmid, uint8_t cause);

#endif
