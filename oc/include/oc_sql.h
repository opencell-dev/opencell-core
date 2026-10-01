/* The core's database (network-core spec §5, §17 decisions 5 and 9): SQLite
 * in WAL mode with synchronous=FULL, behind oc_core_store_t. K, OPc, the
 * network SKn and token secrets are sealed (oc_seal.h); numbers are stored
 * in the full form as text ("+883160655501234"), TMIDs and SQN in the clear.
 *
 * Opening takes the database's lock (PATH.lock, flock): one process at a
 * time, the running oc-core or an `oc-core admin --offline`. It checks the
 * master key against a sealed value kept in the database, so a wrong key is
 * refused at start and not at the first activation. The schema is versioned
 * with PRAGMA user_version; migrations are applied in order, each in its
 * own transaction, after an automatic backup of the database next to it
 * (PATH.v<old>.<unix time>.bak), which holds sealed keys only.
 *
 * Transactions (oc_core_store.h): a write that fails between begin and
 * commit dooms the transaction: nothing more is written and the commit
 * fails and rolls everything back, so oc_core, which commits without
 * looking at each put, never makes half a change durable. A transaction
 * SQLite rolled back by itself (SQLITE_FULL, SQLITE_IOERR, SQLITE_NOMEM,
 * SQLITE_BUSY) counts as failed: the writes after it would otherwise run in
 * autocommit and each become durable. A begin that fails, or a begin inside
 * an open transaction, dooms it the same way. A delete that deletes nothing
 * is not a failure.
 *
 * Every get tells "none" (OC_CORE_STORE_NONE) from "failed"
 * (OC_CORE_STORE_FAILED): a query that could not run or bind, or a row
 * whose sealed keys do not open, is FAILED. */
#ifndef OC_SQL_H
#define OC_SQL_H

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#include "oc_core_store.h"

#define OC_SQL_VERSION 2 /* the schema this build writes */

/* A rollback past v0.2.0 without restoring the backup: v2 is indexes only,
 * so with oc-core stopped, `sqlite3 core.db "<this>"` gives back the exact
 * v1 schema v0.1.x opens, and keeps everything written since (README). */
#define OC_SQL_V2_TO_V1                                                                                        \
    "DROP INDEX audit_number; DROP INDEX cdr_caller; DROP INDEX cdr_called; DROP INDEX token_unused_expiry;" \
    " PRAGMA user_version = 1;"

typedef struct oc_sql oc_sql_t;

typedef struct {
    const char    *path;       /* ":memory:" (tests): no lock, no backup */
    const uint8_t *master_key; /* 32 bytes */
    void (*random)(uint8_t *out, size_t n); /* GCM nonces */
    /* Tests only: the migrations to run instead of this build's (index i
     * takes user_version i to i + 1). NULL: the build's. */
    const char *const *migrations;
    unsigned           nmigrations;
} oc_sql_cfg_t;

/* NULL with the reason in err: can't open, locked by another process, a
 * schema newer than this build, a failed migration or backup, or a master
 * key that does not open this database. */
oc_sql_t       *oc_sql_open(const oc_sql_cfg_t *cfg, char *err, size_t cap);
void            oc_sql_close(oc_sql_t *s);
oc_core_store_t oc_sql_store(oc_sql_t *s);
sqlite3        *oc_sql_db(oc_sql_t *s);      /* for the admin listings (read-only use) */
int             oc_sql_version(oc_sql_t *s); /* PRAGMA user_version */
const char     *oc_sql_backup(oc_sql_t *s);  /* the backup taken before migrating at open, or "" */
unsigned        oc_sql_unseal_failures(oc_sql_t *s); /* rows whose keys did not open (read as failed) */
/* This build's migration i (taking user_version i to i + 1), or NULL. */
const char     *oc_sql_migration(unsigned i);

/* cell.cert_fpr (network-core spec §5), which oc_core does not keep (its
 * cell_put leaves it alone): the pinned certificate's SHA-256, 64
 * lowercase hex digits, or NULL to unpin. 0, OC_CORE_STORE_NONE (no such
 * cell) or OC_CORE_STORE_FAILED. */
int oc_sql_cell_cert_set(oc_sql_t *s, uint32_t cell_id, const char *fpr);
/* For the release job (network-core spec §18.3): up to max unactivated
 * subscribers whose unused token expired at or before now, oldest expiry
 * first. How many, or -1 (the store failed). */
int oc_sql_expired(oc_sql_t *s, uint32_t now, uint8_t (*out)[OC_SIG_NUMBER_LEN], int max);

#endif
