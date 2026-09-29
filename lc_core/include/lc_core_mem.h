/* The in-memory store: plain arrays behind lc_core_store_t, for the host
 * tests and the simulation. A core restarted over the same lc_core_mem_t
 * keeps everything, as it would over its database. CDRs and audit records
 * keep the newest LC_CORE_MEM_LOG of each.
 *
 * The token table is sized separately from LC_CORE_MEM_SUBS: token_void only
 * deletes a number's *unused* tokens (network-core spec §5), so a used token
 * is kept forever, and the table must have room for that history to grow
 * past one live token per subscriber. */
#ifndef LC_CORE_MEM_H
#define LC_CORE_MEM_H

#include "lc_core_store.h"

#define LC_CORE_MEM_KEYS   4u
#define LC_CORE_MEM_CELLS  16u
#define LC_CORE_MEM_SUBS   64u
#define LC_CORE_MEM_TOKENS (2u * LC_CORE_MEM_SUBS)
#define LC_CORE_MEM_AVS    256u
#define LC_CORE_MEM_LOG    64u
#define LC_CORE_MEM_LISTS  8u

typedef struct {
    lc_core_netkey_t    key[LC_CORE_MEM_KEYS];
    unsigned            nkey;
    lc_core_cell_t      cell[LC_CORE_MEM_CELLS];
    unsigned            ncell;
    uint16_t            list_id[LC_CORE_MEM_LISTS];
    lc_sig_chan_list_t  list[LC_CORE_MEM_LISTS];
    unsigned            nlist;
    lc_core_sub_t       sub[LC_CORE_MEM_SUBS];
    unsigned            nsub;
    lc_core_token_t     token[LC_CORE_MEM_TOKENS];
    unsigned            ntoken;
    lc_core_av_issued_t av[LC_CORE_MEM_AVS];
    unsigned            nav;
    lc_core_loc_t       loc[LC_CORE_MEM_SUBS];
    unsigned            nloc;
    lc_core_cdr_t       cdr[LC_CORE_MEM_LOG];
    unsigned            ncdr;   /* ever added; the newest is cdr[(ncdr - 1) % LC_CORE_MEM_LOG] */
    lc_core_audit_t     audit[LC_CORE_MEM_LOG];
    unsigned            naudit; /* likewise */
} lc_core_mem_data_t;

/* fail_reads: which lookups fail (LC_CORE_STORE_FAILED) while it is set */
#define LC_CORE_MEM_FAIL_SUB_GET   1u
#define LC_CORE_MEM_FAIL_LOC_GET   2u
#define LC_CORE_MEM_FAIL_AV_NEWEST 4u

typedef struct {
    lc_core_mem_data_t d;
    lc_core_mem_data_t undo;        /* d as it was at begin */
    int                in_txn;
    int                txn_failed;   /* a write inside this transaction failed: commit must undo it */
    int                refusing;     /* its begin failed: every write until commit is refused */
    int                fail_commits; /* test hook: the next n commits fail (and undo) */
    int                fail_begins;  /* test hook: the next n begins fail (and doom their transaction) */
    unsigned           fail_reads;   /* test hook: LC_CORE_MEM_FAIL_* */
    unsigned           commits;      /* successful commits */
    unsigned           refused;      /* writes refused after a failed begin */
} lc_core_mem_t;

void            lc_core_mem_init(lc_core_mem_t *m);
lc_core_store_t lc_core_mem_store(lc_core_mem_t *m);

/* The newest audit record of event (NULL if none is kept): for tests. */
const lc_core_audit_t *lc_core_mem_audit(const lc_core_mem_t *m, uint8_t event);

#endif
