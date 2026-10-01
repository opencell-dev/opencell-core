/* Shared between oc_core's own files; not part of its interface. */
#ifndef OC_CORE_INT_H
#define OC_CORE_INT_H

#include "oc_core.h"

#define OC_CORE_US(s) ((uint64_t)(s) * 1000000ull)

uint32_t oc_core_unix(oc_core_t *k);
void     oc_core_logf(oc_core_t *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* To the link of cell_id: 0, or -1 when the cell has no link. */
int      oc_core_send(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m);
int      oc_core_linked(const oc_core_t *k, uint32_t cell_id);
void     oc_core_audit(oc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                       const char *detail);
/* The store's begin, checked (oc_core_store.h): 0, or -1 when it failed -
 * logged, and the doomed transaction already closed with commit. The
 * caller then refuses whatever it was doing, with nothing sent. */
int      oc_core_begin(oc_core_t *k);

/* oc_core_hss.c: ACT_FWD, AV_REQ, RESYNC from a cell */
void     oc_core_hss_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m);

/* oc_core_reg.c: the number's location if it is live (an expired one is
 * deleted): 0, OC_CORE_STORE_NONE (none live), or OC_CORE_STORE_FAILED. */
int      oc_core_loc_live(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_loc_t *out);
/* LOC_CANCEL and its audit for a location the caller already deleted from
 * the store, atomically with whatever else it changed (e.g. disabling): a
 * failed send is logged but still audited, since the location really is
 * gone. rand: the RAND that proved the registration cancelled, or NULL (all
 * zero: whatever the TMID registered with). why, if not NULL, prefixes the
 * audit detail ("<why>, cause N"). */
void     oc_core_loc_send_cancel(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], uint32_t cell_id,
                                 uint32_t tmid, uint8_t cause, const uint8_t *rand, const char *why);
/* LOC_UPDATE and LOC_PURGE from a cell */
void     oc_core_reg_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m);
/* Issued vectors older than a day go (network-core spec §5 av_issued). */
void     oc_core_reg_tick(oc_core_t *k);

/* oc_core_switch.c: CALL_* and MEDIA from a cell, the call timers, and a
 * cell whose link went (every call with a leg on it ends, cause 5) */
void     oc_core_sw_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m);
void     oc_core_sw_tick(oc_core_t *k);
void     oc_core_sw_cell_gone(oc_core_t *k, uint32_t cell_id);

/* oc_core_peer.c: to core_id's link if it is up: 0, or -1 */
int      oc_core_peer_send(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m);
/* the peers' liveness, from oc_core_tick */
void     oc_core_peer_tick(oc_core_t *k);
/* 1 if core_id's CALL_SETUP budget has a token now (and one is spent), else
 * 0 (logged, at most once a second): review M3. 0 too if core_id is not an
 * up peer (on_setup only calls this for one, so that should not happen). */
int      oc_core_peer_setup_allowed(oc_core_t *k, uint16_t core_id);
/* oc_core_switch.c: OCSS call control from an up peer, and a peer whose
 * link went (every call with a leg on it ends, cause 5) */
void     oc_core_sw_peer_rx(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m);
void     oc_core_sw_peer_gone(oc_core_t *k, uint16_t core_id);

#endif
