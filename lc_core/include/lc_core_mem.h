/* The in-memory store: plain arrays behind lc_core_store_t, for the host
 * tests and the simulation. A core restarted over the same lc_core_mem_t
 * keeps everything, as it would over its database. CDRs and audit records
 * keep the newest LC_CORE_MEM_LOG of each. */
#ifndef LC_CORE_MEM_H
#define LC_CORE_MEM_H

#include "lc_core_store.h"

#define LC_CORE_MEM_KEYS  4u
#define LC_CORE_MEM_CELLS 16u
#define LC_CORE_MEM_SUBS  64u
#define LC_CORE_MEM_AVS   256u
#define LC_CORE_MEM_LOG   64u

typedef struct {
    lc_core_netkey_t    key[LC_CORE_MEM_KEYS];
    unsigned            nkey;
    lc_core_cell_t      cell[LC_CORE_MEM_CELLS];
    unsigned            ncell;
    lc_core_sub_t       sub[LC_CORE_MEM_SUBS];
    unsigned            nsub;
    lc_core_token_t     token[LC_CORE_MEM_SUBS];
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

typedef struct {
    lc_core_mem_data_t d;
    lc_core_mem_data_t undo;        /* d as it was at begin */
    int                in_txn;
    int                fail_commits; /* test hook: the next n commits fail (and undo) */
    unsigned           commits;      /* successful commits */
} lc_core_mem_t;

void            lc_core_mem_init(lc_core_mem_t *m);
lc_core_store_t lc_core_mem_store(lc_core_mem_t *m);

/* The newest audit record of event (NULL if none is kept): for tests. */
const lc_core_audit_t *lc_core_mem_audit(const lc_core_mem_t *m, uint8_t event);

#endif
