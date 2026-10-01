/* The in-memory store: plain arrays behind oc_core_store_t, for the host
 * tests and the simulation. A core restarted over the same oc_core_mem_t
 * keeps everything, as it would over its database. CDRs and audit records
 * keep the newest OC_CORE_MEM_LOG of each.
 *
 * The token table is sized separately from OC_CORE_MEM_SUBS: token_void only
 * deletes a number's *unused* tokens (network-core spec §5), so a used token
 * is kept forever, and the table must have room for that history to grow
 * past one live token per subscriber. */
#ifndef OC_CORE_MEM_H
#define OC_CORE_MEM_H

#include "oc_core_store.h"

#define OC_CORE_MEM_KEYS   4u
#define OC_CORE_MEM_CELLS  16u
#define OC_CORE_MEM_SUBS   64u
#define OC_CORE_MEM_TOKENS (2u * OC_CORE_MEM_SUBS)
#define OC_CORE_MEM_AVS    256u
#define OC_CORE_MEM_LOG    64u
#define OC_CORE_MEM_LISTS  8u

typedef struct {
    oc_core_netkey_t    key[OC_CORE_MEM_KEYS];
    unsigned            nkey;
    oc_core_cell_t      cell[OC_CORE_MEM_CELLS];
    unsigned            ncell;
    uint16_t            list_id[OC_CORE_MEM_LISTS];
    oc_sig_chan_list_t  list[OC_CORE_MEM_LISTS];
    unsigned            nlist;
    oc_core_sub_t       sub[OC_CORE_MEM_SUBS];
    unsigned            nsub;
    oc_core_token_t     token[OC_CORE_MEM_TOKENS];
    unsigned            ntoken;
    oc_core_av_issued_t av[OC_CORE_MEM_AVS];
    unsigned            nav;
    oc_core_loc_t       loc[OC_CORE_MEM_SUBS];
    unsigned            nloc;
    oc_core_cdr_t       cdr[OC_CORE_MEM_LOG];
    unsigned            ncdr;   /* ever added; the newest is cdr[(ncdr - 1) % OC_CORE_MEM_LOG] */
    oc_core_audit_t     audit[OC_CORE_MEM_LOG];
    unsigned            naudit; /* likewise */
} oc_core_mem_data_t;

/* fail_reads: which lookups fail (OC_CORE_STORE_FAILED) while it is set */
#define OC_CORE_MEM_FAIL_SUB_GET     1u
#define OC_CORE_MEM_FAIL_LOC_GET     2u
#define OC_CORE_MEM_FAIL_AV_NEWEST   4u
#define OC_CORE_MEM_FAIL_SUB_BY_TMID 8u
#define OC_CORE_MEM_FAIL_NETKEY_GET  16u
#define OC_CORE_MEM_FAIL_CELL_GET    32u
#define OC_CORE_MEM_FAIL_LIST_GET    64u
#define OC_CORE_MEM_FAIL_TOKEN_GET   128u
#define OC_CORE_MEM_FAIL_AV_GET      256u
#define OC_CORE_MEM_FAIL_LIST_VER_GET 512u

typedef struct {
    oc_core_mem_data_t d;
    oc_core_mem_data_t undo;        /* d as it was at begin */
    int                in_txn;
    int                txn_failed;   /* a write inside this transaction failed: commit must undo it */
    int                refusing;     /* its begin failed: every write until commit is refused */
    int                fail_commits; /* test hook: the next n commits fail (and undo) */
    int                fail_begins;  /* test hook: the next n begins fail (and doom their transaction) */
    unsigned           fail_reads;   /* test hook: OC_CORE_MEM_FAIL_* */
    unsigned           commits;      /* successful commits */
    unsigned           refused;      /* writes refused after a failed begin */
} oc_core_mem_t;

void            oc_core_mem_init(oc_core_mem_t *m);
oc_core_store_t oc_core_mem_store(oc_core_mem_t *m);

/* The newest audit record of event (NULL if none is kept): for tests. */
const oc_core_audit_t *oc_core_mem_audit(const oc_core_mem_t *m, uint8_t event);

#endif
