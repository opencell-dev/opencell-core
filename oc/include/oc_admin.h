/* `oc-core admin ...` (network-core spec §4.2, §17 decision 1): the
 * operator's commands, run inside the daemon (over the admin socket) or,
 * with --offline, straight on a stopped core's database. Either way they go
 * through oc_core and the store, so a disable in the daemon sends its
 * LOC_CANCEL at once. Every command - done, refused, failed or not a
 * command at all - is written to the audit log (event OC_CORE_AUDIT_ADMIN,
 * "u<uid> [(sudo u<uid>)] [(refused)|(usage)] <command line>", with the
 * subscriber's number in the record's number column for sub commands; C0
 * and C1 control characters and bytes that are not UTF-8 shown as '?'). An
 * output buffer that could not grow (oc_buf_t.err) makes the command's result 1.
 *
 *   status
 *   net init [--period S]                  the network key pair (first setup)
 *   cell add ID NAME [--mode part15|part97] [--list N]
 *   cell mode ID part15|part97             the cell reconnects to take it
 *   cell revoke ID | cell list
 *   sub add [NUMBER] | sub issue NUMBER [--valid-h H] | sub disable NUMBER | sub list
 *   loc | cdr [N] | audit [N]
 *   list set ID MHZ[:fixed],...|none [--force] | list show
 *                                          --force: replace a stored list that
 *                                          can't be read (a damaged row), at the
 *                                          version after the last one written
 *   import-ocb-hss FILE                    (--offline only) ocbench's bench HSS
 *
 * A store that can't answer is reported as a store error, never as "not
 * found" or "exists" (oc_core_store.h), and nothing is changed on it.
 *
 * Numbers are taken in any full form (+883-1-606-555-01234) and shown in
 * the canonical one (+883160655501234). No key material (SKn, K, OPc, token
 * secrets) is ever written to out or to the log; an activation code is the
 * one secret `sub issue` shows, as it must. */
#ifndef OC_ADMIN_H
#define OC_ADMIN_H

#include <stddef.h>
#include <stdint.h>

#include "oc_core.h"
#include "oc_sql.h"

typedef struct {
    char  *p; /* NUL-terminated */
    size_t n, cap;
    int    err; /* an append did not fit and could not grow: p is incomplete (the caller clears it) */
} oc_buf_t;

void oc_buf_printf(oc_buf_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void oc_buf_free(oc_buf_t *b);

typedef struct {
    oc_sql_t              *sql;
    const oc_core_route_t *route;
    const oc_core_cfg_t   *cfg;
    oc_core_t             *core; /* the daemon's; NULL offline (then a core of its own, once the key exists) */
    void (*random)(uint8_t *out, size_t n);
    uint64_t (*now_us)(void);                       /* the daemon's oc_core clock */
    void (*drop_cell)(void *ctx, uint32_t cell_id); /* the daemon closes the cell's link; NULL offline */
    void    *ctx;
    /* who asked, for the audit record: the admin socket's peer uid
     * (SO_PEERCRED; who may connect at all is the socket's mode, 0660
     * root:oc-admin, spec §17.1), or offline getuid(), taken before the
     * process becomes the database's owner. Recorded only:
     * nothing here grants or refuses by it. */
    uint32_t uid;
    /* offline as root under sudo: SUDO_UID, the operator behind uid 0,
     * recorded as "u0 (sudo u<N>)"; 0: none. As the environment claims it:
     * recorded only. */
    uint32_t sudo_uid;
    /* private */
    oc_core_t own;
    int       have_own;
    uint8_t   audit_number[OC_SIG_NUMBER_LEN]; /* the number this command named, for its audit record */
} oc_admin_t;

/* Runs one command: argv[0] is its first word ("sub"). Output goes to out.
 * 0 done, 1 refused or failed (out says why), 2 not a command (out has the
 * usage). */
int oc_admin_run(oc_admin_t *a, int argc, char **argv, oc_buf_t *out);

/* "917.25,922.25:fixed" (MHz on the 915 grid, at most OC_SIG_CHAN_MAX, no
 * spaces), or "" / "none" for an empty list. 0, or -1 with err set. */
int oc_chan_parse(const char *text, oc_sig_chan_list_t *out, char *err, size_t cap);

/* ocbench's text HSS (tools/ocbench/ocb_hss.h in opencell-firmware before
 * network core 2): its network key pair and its subscribers, with their
 * TMIDs, K, OPc and SQN, so activated terminals keep working without a new
 * QR code. All or nothing. Tokens are not carried over (their ids have no
 * block index, spec §14.3). The keys go into the store (sealed there) and
 * nowhere else. 0 or 1, as oc_admin_run. */
int oc_import_ocb_hss(oc_admin_t *a, const char *path, oc_buf_t *out);

#endif
