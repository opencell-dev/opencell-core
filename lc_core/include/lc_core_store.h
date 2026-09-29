/* What lc_core keeps (network-core spec §5), behind an interface: records
 * in the clear as lc_core uses them, one function per question it asks.
 * lc_core_mem.h is the in-memory store (tests, simulation); plan 8's SQLite
 * store seals k, opc, sk and token secrets at rest behind the same calls.
 *
 * Every function returns 0, or -1 (not found, full, or failed). A write
 * (put or delete) outside begin/commit is durable when it returns; between
 * begin and commit the writes are one change that commit makes durable or,
 * failing, undoes. A write (put or delete) that fails between begin and
 * commit, other than a delete that finds nothing to delete, still dooms the
 * whole transaction: commit must then return -1 and undo everything done
 * since begin, even if the caller who saw that write's own -1 pressed on
 * regardless (a store full of authentication vectors must never let a cell
 * walk away with a vector whose av_issued row never made it to disk).
 * Deleting nothing is not itself a failure worth dooming a transaction over:
 * a delete of a key that was never there, or is already gone, returns -1
 * but leaves the transaction it happened in undoomed. */
#ifndef LC_CORE_STORE_H
#define LC_CORE_STORE_H

#include "lc_sig.h"

typedef struct {
    uint16_t key_id;
    uint8_t  sk[32], pk[32]; /* X25519, for activation (QR carries key_id + pk) */
    uint16_t period_s;       /* registration period announced with this key */
    uint32_t created;
} lc_core_netkey_t;

typedef struct {
    uint32_t cell_id;
    char     name[32];
    uint8_t  mode;     /* lc_sig_mode_t */
    uint8_t  enabled;
    uint16_t list_id;  /* channel-list group (channel-list spec §8): its cells share one list; 0 none */
    uint64_t boot_id;  /* from the cell's last HELLO */
    uint32_t last_seen;
} lc_core_cell_t;

typedef enum { LC_CORE_SUB_ACTIVE = 1, LC_CORE_SUB_DISABLED = 2 } lc_core_sub_state_t;

typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN]; /* full form, the key */
    uint8_t  state;                     /* lc_core_sub_state_t */
    uint8_t  activated;
    uint32_t tmid;                      /* bound terminal, 0 = none */
    uint8_t  k[16], opc[16];
    uint64_t sqn;                       /* the last SQN issued */
    uint32_t created, updated;
} lc_core_sub_t;

typedef struct {
    uint8_t  token_id[8]; /* block index (2, big-endian) | random (6) */
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint8_t  secret[16];
    uint32_t expiry;
    uint32_t used_at;     /* 0 = unused */
    uint32_t used_by_tmid;
} lc_core_token_t;

typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint8_t  rand[16], xres[8]; /* (number, rand) is the key */
    uint64_t sqn;
    uint32_t cell_id;           /* issued to */
    uint32_t issued;
    uint8_t  confirmed;         /* a LOC_UPDATE proved it */
} lc_core_av_issued_t;

typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint32_t cell_id, tmid;
    uint32_t expires;
    uint64_t sqn;     /* the SQN of the vector that proved it (network-core spec §19.2) */
    uint8_t  rand[16]; /* ...and its RAND: LOC_CANCEL(moved) names the registration it cancels */
} lc_core_loc_t;

typedef struct {
    uint8_t  caller[LC_SIG_NUMBER_LEN], called[LC_SIG_NUMBER_LEN];
    uint32_t cell_a, cell_b; /* cell_b 0: a service (the echo service) */
    uint32_t setup, answer, end; /* unix s; answer 0 = never answered */
    uint8_t  cause;
} lc_core_cdr_t;

typedef enum {
    LC_CORE_AUDIT_ACTIVATE = 1, LC_CORE_AUDIT_ACT_FAIL, LC_CORE_AUDIT_REGISTER, LC_CORE_AUDIT_AUTH_FAIL,
    LC_CORE_AUDIT_RESYNC, LC_CORE_AUDIT_LOC_CANCEL, LC_CORE_AUDIT_TOKEN_ISSUE, LC_CORE_AUDIT_SUB_DISABLE,
    LC_CORE_AUDIT_CELL_REJECT
} lc_core_audit_event_t;

typedef struct {
    uint32_t ts;
    uint8_t  event; /* lc_core_audit_event_t */
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint32_t tmid, cell_id;
    char     detail[48];
} lc_core_audit_t;

typedef struct {
    void *ctx;
    int (*begin)(void *ctx);
    int (*commit)(void *ctx);
    int (*netkey_get)(void *ctx, uint16_t key_id, lc_core_netkey_t *out);
    int (*netkey_put)(void *ctx, const lc_core_netkey_t *k);
    int (*cell_get)(void *ctx, uint32_t cell_id, lc_core_cell_t *out);
    int (*cell_put)(void *ctx, const lc_core_cell_t *c);
    /* channel lists, one per list group (channel-list spec §8; list_id 1-65535) */
    int (*list_get)(void *ctx, uint16_t list_id, lc_sig_chan_list_t *out);
    int (*list_put)(void *ctx, uint16_t list_id, const lc_sig_chan_list_t *l); /* insert or replace */
    int (*sub_get)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_sub_t *out);
    int (*sub_by_tmid)(void *ctx, uint32_t tmid, lc_core_sub_t *out); /* activated and bound to tmid */
    int (*sub_put)(void *ctx, const lc_core_sub_t *s);                /* insert or replace */
    int (*token_get)(void *ctx, const uint8_t token_id[8], lc_core_token_t *out);
    int (*token_put)(void *ctx, const lc_core_token_t *t);
    int (*token_void)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN]); /* delete its unused tokens */
    int (*av_put)(void *ctx, const lc_core_av_issued_t *a);
    int (*av_get)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                  lc_core_av_issued_t *out);
    int (*av_drop_cell)(void *ctx, uint32_t cell_id);  /* the cell's unconfirmed vectors */
    int (*av_del_number)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN]); /* all of the number's (§19.3) */
    /* the highest SQN among the number's confirmed vectors issued to any
     * cell but not_cell (§19.2's floor for a claim from not_cell); -1: none */
    int (*av_newest_confirmed)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t not_cell,
                               uint64_t *sqn);
    int (*av_prune)(void *ctx, uint32_t issued_before);
    int (*loc_get)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out);
    int (*loc_put)(void *ctx, const lc_core_loc_t *l);
    int (*loc_del)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN]);
    int (*loc_purge_cell)(void *ctx, uint32_t cell_id);
    int (*cdr_add)(void *ctx, const lc_core_cdr_t *c);
    int (*audit_add)(void *ctx, const lc_core_audit_t *a);
} lc_core_store_t;

#endif
