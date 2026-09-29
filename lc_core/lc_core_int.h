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
/* The store's begin, checked (lc_core_store.h): 0, or -1 when it failed -
 * logged, and the doomed transaction already closed with commit. The
 * caller then refuses whatever it was doing, with nothing sent. */
int      lc_core_begin(lc_core_t *k);

/* lc_core_hss.c: ACT_FWD, AV_REQ, RESYNC from a cell */
void     lc_core_hss_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);

/* lc_core_reg.c: the number's location if it is live (an expired one is
 * deleted): 0, LC_CORE_STORE_NONE (none live), or LC_CORE_STORE_FAILED. */
int      lc_core_loc_live(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out);
/* LOC_CANCEL and its audit for a location the caller already deleted from
 * the store, atomically with whatever else it changed (e.g. disabling): a
 * failed send is logged but still audited, since the location really is
 * gone. rand: the RAND that proved the registration cancelled, or NULL (all
 * zero: whatever the TMID registered with). why, if not NULL, prefixes the
 * audit detail ("<why>, cause N"). */
void     lc_core_loc_send_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t cell_id,
                                 uint32_t tmid, uint8_t cause, const uint8_t *rand, const char *why);
/* LOC_UPDATE and LOC_PURGE from a cell */
void     lc_core_reg_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);
/* Issued vectors older than a day go (network-core spec §5 av_issued). */
void     lc_core_reg_tick(lc_core_t *k);

/* lc_core_switch.c: CALL_* and MEDIA from a cell, the call timers, and a
 * cell whose link went (every call with a leg on it ends, cause 5) */
void     lc_core_sw_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);
void     lc_core_sw_tick(lc_core_t *k);
void     lc_core_sw_cell_gone(lc_core_t *k, uint32_t cell_id);

#endif
