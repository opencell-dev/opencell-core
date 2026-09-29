#define _GNU_SOURCE
#include "oc_sql.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "oc_sig_keys.h"
#include "oc_seal.h"

/* Schema v1 (network-core spec §5, the tables plan 8 uses; route, block and
 * binding_idx come with plans 10-11). meta holds the master-key check.
 * location keeps the SQN and RAND of the vector that proved it (§19.2,
 * LOC_CANCEL); av_issued_newest answers av_newest_confirmed. */
static const char SCHEMA_V1[] =
    "CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL);"
    "CREATE TABLE network(key_id INTEGER PRIMARY KEY, sk_enc BLOB NOT NULL, pk BLOB NOT NULL,"
    " period_s INTEGER NOT NULL, created INTEGER NOT NULL);"
    "CREATE TABLE cell(cell_id INTEGER PRIMARY KEY, name TEXT NOT NULL, cert_fpr TEXT, mode INTEGER NOT NULL,"
    " enabled INTEGER NOT NULL, list_id INTEGER NOT NULL DEFAULT 0, boot_id INTEGER NOT NULL DEFAULT 0,"
    " last_seen INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE subscriber(number TEXT PRIMARY KEY, state INTEGER NOT NULL, tmid INTEGER NOT NULL,"
    " activated INTEGER NOT NULL, k_enc BLOB NOT NULL, opc_enc BLOB NOT NULL, sqn INTEGER NOT NULL,"
    " created INTEGER NOT NULL, updated INTEGER NOT NULL);"
    "CREATE INDEX subscriber_tmid ON subscriber(tmid) WHERE activated = 1;"
    "CREATE TABLE token(token_id BLOB PRIMARY KEY, number TEXT NOT NULL, secret_enc BLOB NOT NULL,"
    " expiry INTEGER NOT NULL, used_at INTEGER NOT NULL, used_by_tmid INTEGER NOT NULL);"
    "CREATE UNIQUE INDEX token_one_unused ON token(number) WHERE used_at = 0;"
    "CREATE TABLE av_issued(number TEXT NOT NULL, rand BLOB NOT NULL, xres BLOB NOT NULL, sqn INTEGER NOT NULL,"
    " cell_id INTEGER NOT NULL, issued INTEGER NOT NULL, confirmed INTEGER NOT NULL, PRIMARY KEY(number, rand));"
    "CREATE INDEX av_issued_newest ON av_issued(number, confirmed, sqn);"
    "CREATE TABLE location(number TEXT PRIMARY KEY, cell_id INTEGER NOT NULL, tmid INTEGER NOT NULL,"
    " expires INTEGER NOT NULL, sqn INTEGER NOT NULL, rand BLOB NOT NULL);"
    "CREATE TABLE chan_list(list_id INTEGER PRIMARY KEY, ver INTEGER NOT NULL, entries BLOB NOT NULL);"
    "CREATE TABLE cdr(id INTEGER PRIMARY KEY AUTOINCREMENT, caller TEXT NOT NULL, called TEXT NOT NULL,"
    " cell_a INTEGER NOT NULL, cell_b INTEGER NOT NULL, setup INTEGER NOT NULL, answer INTEGER NOT NULL,"
    " \"end\" INTEGER NOT NULL, cause INTEGER NOT NULL);"
    "CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event INTEGER NOT NULL,"
    " number TEXT, tmid INTEGER NOT NULL, cell_id INTEGER NOT NULL, detail TEXT NOT NULL);";

static const char *const MIGRATIONS[] = { SCHEMA_V1 };

static const char KEY_CHECK[] = "OpenCell master key";

struct oc_sql {
    sqlite3 *db;
    uint8_t  key[32];
    void (*random)(uint8_t *out, size_t n);
    int      lock_fd;
    int      in_txn, began, failed;
    unsigned unseal_failures;
    char     backup[600];
};

/* ---- helpers ---- */

static sqlite3_stmt *prep(oc_sql_t *s, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) != SQLITE_OK) return NULL;
    return st;
}

/* A write: 0, or -1 (then, inside a transaction, the commit will fail). */
static int done(oc_sql_t *s, sqlite3_stmt *st)
{
    int rc = st != NULL ? sqlite3_step(st) : SQLITE_ERROR;
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return 0;
    if (s->in_txn) s->failed = 1;
    return -1;
}

/* A prepared write whose binds returned b (their codes OR-ed, so 0 when
 * every one was SQLITE_OK): a value that could not be bound is a failed
 * write, never a NULL in its column. */
static int run(oc_sql_t *s, sqlite3_stmt *st, int b)
{
    if (st != NULL && b != SQLITE_OK) {
        sqlite3_finalize(st);
        st = NULL;
    }
    return done(s, st);
}

/* A get (oc_core_store.h): steps st, whose binds returned b, once: 0 (a
 * row, to be read), OC_CORE_STORE_NONE (no row) or OC_CORE_STORE_FAILED (no
 * statement, a bind that failed, or an error). */
static int get_step(sqlite3_stmt *st, int b)
{
    if (st == NULL || b != SQLITE_OK) return OC_CORE_STORE_FAILED;
    int rc = sqlite3_step(st);
    return rc == SQLITE_ROW ? 0 : rc == SQLITE_DONE ? OC_CORE_STORE_NONE : OC_CORE_STORE_FAILED;
}

/* A write refused before it starts: inside a failed transaction nothing is
 * written. SQLite rolls a transaction back by itself on some errors
 * (SQLITE_FULL, SQLITE_IOERR, SQLITE_NOMEM, SQLITE_BUSY), and the statements
 * after would run in autocommit, each durable on its own: a transaction
 * that has left SQLite's hands is doomed too. */
static int blocked(oc_sql_t *s)
{
    if (s->in_txn && s->began && !s->failed && sqlite3_get_autocommit(s->db)) s->failed = 1;
    /* outside begin/commit a write is durable when it returns: not if the
     * connection sits in a transaction the store did not open (one a failed
     * ROLLBACK left, say), where it would wait for someone's COMMIT */
    if (!s->in_txn && !sqlite3_get_autocommit(s->db)) return 1;
    return s->in_txn && s->failed;
}

static void num_text(const uint8_t n[OC_SIG_NUMBER_LEN], char out[OC_SIG_NUMBER_TEXT]) { oc_sig_number_to_text(n, out); }

static int num_col(sqlite3_stmt *st, int col, uint8_t out[OC_SIG_NUMBER_LEN])
{
    const char *t = (const char *)sqlite3_column_text(st, col);
    memset(out, 0, OC_SIG_NUMBER_LEN);
    return t != NULL && oc_sig_number_to_bcd(t, strlen(t), out) == 0 ? 0 : -1;
}

static void blob_col(sqlite3_stmt *st, int col, uint8_t *out, size_t n)
{
    const void *b = sqlite3_column_blob(st, col);
    memset(out, 0, n);
    if (b != NULL && (size_t)sqlite3_column_bytes(st, col) == n) memcpy(out, b, n);
}

static int seal_bind(oc_sql_t *s, sqlite3_stmt *st, int idx, const char *table, const char *column,
                     const uint8_t *pk, size_t pk_n, const uint8_t *pt, size_t n)
{
    uint8_t nonce[12], blob[OC_SEAL_PT_MAX + OC_SEAL_OVERHEAD];
    s->random(nonce, sizeof(nonce));
    if (oc_seal(s->key, table, column, pk, pk_n, pt, n, nonce, blob) != 0) return -1;
    return sqlite3_bind_blob(st, idx, blob, (int)(n + OC_SEAL_OVERHEAD), SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
}

static int unseal_col(oc_sql_t *s, sqlite3_stmt *st, int col, const char *table, const char *column,
                      const uint8_t *pk, size_t pk_n, uint8_t *pt, size_t n)
{
    const uint8_t *b = sqlite3_column_blob(st, col);
    size_t bn = (size_t)sqlite3_column_bytes(st, col);
    if (b == NULL || bn != n + OC_SEAL_OVERHEAD || oc_unseal(s->key, table, column, pk, pk_n, b, bn, pt) != 0) {
        s->unseal_failures++;
        return -1;
    }
    return 0;
}

#define S(c) ((oc_sql_t *)(c))

/* ---- transactions ---- */

static int begin(void *c)
{
    oc_sql_t *s = S(c);
    if (s->in_txn) { /* already inside one: that one is doomed (oc_core_store.h) */
        s->failed = 1;
        return -1;
    }
    s->in_txn = 1;
    s->began = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    s->failed = !s->began; /* puts until commit write nothing, and commit fails */
    return s->began ? 0 : -1;
}

static int commit(void *c)
{
    oc_sql_t *s = S(c);
    if (!s->in_txn) return -1;
    int ok = !blocked(s) && s->began && sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok && s->began && !sqlite3_get_autocommit(s->db)) {
        /* a ROLLBACK can fail while a statement is still running; tried
         * twice, and if the transaction is still open blocked() refuses
         * every write outside begin/commit and begin fails, so nothing is
         * written into it */
        if (sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK || !sqlite3_get_autocommit(s->db)) {
            sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
        }
    }
    s->in_txn = s->began = s->failed = 0;
    return ok ? 0 : -1;
}

/* ---- network keys ---- */

static void key_pk(uint16_t key_id, uint8_t pk[2])
{
    pk[0] = (uint8_t)(key_id >> 8);
    pk[1] = (uint8_t)key_id;
}

static int netkey_get(void *c, uint16_t key_id, oc_core_netkey_t *out)
{
    oc_sql_t *s = S(c);
    uint8_t pk[2];
    sqlite3_stmt *st = prep(s, "SELECT sk_enc, pk, period_s, created FROM network WHERE key_id = ?");
    int b = st != NULL ? sqlite3_bind_int(st, 1, key_id) : SQLITE_ERROR;
    int rc = get_step(st, b);
    key_pk(key_id, pk);
    memset(out, 0, sizeof(*out));
    if (rc == 0) {
        if (unseal_col(s, st, 0, "network", "sk", pk, 2, out->sk, sizeof(out->sk)) != 0) {
            rc = OC_CORE_STORE_FAILED;
        } else {
            out->key_id = key_id;
            blob_col(st, 1, out->pk, sizeof(out->pk));
            out->period_s = (uint16_t)sqlite3_column_int(st, 2);
            out->created = (uint32_t)sqlite3_column_int64(st, 3);
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int netkey_put(void *c, const oc_core_netkey_t *k)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    uint8_t pk[2];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO network(key_id, sk_enc, pk, period_s, created) VALUES(?,?,?,?,?)");
    if (st == NULL) return run(s, st, b);
    key_pk(k->key_id, pk);
    b |= sqlite3_bind_int(st, 1, k->key_id);
    b |= seal_bind(s, st, 2, "network", "sk", pk, 2, k->sk, sizeof(k->sk));
    b |= sqlite3_bind_blob(st, 3, k->pk, sizeof(k->pk), SQLITE_TRANSIENT);
    b |= sqlite3_bind_int(st, 4, k->period_s);
    b |= sqlite3_bind_int64(st, 5, k->created);
    return run(s, st, b);
}

/* ---- cells ---- */

static int cell_get(void *c, uint32_t cell_id, oc_core_cell_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT name, mode, enabled, list_id, boot_id, last_seen FROM cell WHERE cell_id = ?");
    int b = st != NULL ? sqlite3_bind_int64(st, 1, cell_id) : SQLITE_ERROR;
    int rc = get_step(st, b);
    memset(out, 0, sizeof(*out));
    if (rc == 0) {
        const char *name = (const char *)sqlite3_column_text(st, 0);
        if (name == NULL) {
            rc = OC_CORE_STORE_FAILED; /* NOT NULL: only out of memory gets here */
        } else {
            out->cell_id = cell_id;
            snprintf(out->name, sizeof(out->name), "%s", name);
            out->mode = (uint8_t)sqlite3_column_int(st, 1);
            out->enabled = (uint8_t)sqlite3_column_int(st, 2);
            out->list_id = (uint16_t)sqlite3_column_int(st, 3);
            out->boot_id = (uint64_t)sqlite3_column_int64(st, 4);
            out->last_seen = (uint32_t)sqlite3_column_int64(st, 5);
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int cell_put(void *c, const oc_core_cell_t *x)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    if (blocked(s)) return -1;
    /* an upsert: cert_fpr (plan 9) is not oc_core's and survives */
    sqlite3_stmt *st = prep(s, "INSERT INTO cell(cell_id, name, mode, enabled, list_id, boot_id, last_seen)"
                               " VALUES(?,?,?,?,?,?,?) ON CONFLICT(cell_id) DO UPDATE SET name = excluded.name,"
                               " mode = excluded.mode, enabled = excluded.enabled, list_id = excluded.list_id,"
                               " boot_id = excluded.boot_id, last_seen = excluded.last_seen");
    if (st != NULL) {
        b |= sqlite3_bind_int64(st, 1, x->cell_id);
        b |= sqlite3_bind_text(st, 2, x->name, -1, SQLITE_TRANSIENT);
        b |= sqlite3_bind_int(st, 3, x->mode);
        b |= sqlite3_bind_int(st, 4, x->enabled);
        b |= sqlite3_bind_int(st, 5, x->list_id);
        b |= sqlite3_bind_int64(st, 6, (sqlite3_int64)x->boot_id);
        b |= sqlite3_bind_int64(st, 7, x->last_seen);
    }
    return run(s, st, b);
}

/* ---- channel lists: count x { freq_hz (4, BE), flags (1) } ---- */

static int list_get(void *c, uint16_t list_id, oc_sig_chan_list_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT ver, entries FROM chan_list WHERE list_id = ?");
    int b = st != NULL ? sqlite3_bind_int(st, 1, list_id) : SQLITE_ERROR;
    int rc = get_step(st, b);
    memset(out, 0, sizeof(*out));
    if (rc == 0) {
        const uint8_t *e = sqlite3_column_blob(st, 1);
        int n = sqlite3_column_bytes(st, 1);
        if (n % 5 != 0 || n / 5 > (int)OC_SIG_CHAN_MAX || (n > 0 && e == NULL)) {
            rc = OC_CORE_STORE_FAILED; /* a row list_put never wrote */
        } else {
            out->ver = (uint8_t)sqlite3_column_int(st, 0);
            out->count = (uint8_t)(n / 5);
            for (int i = 0; i < out->count; i++) {
                out->freq_hz[i] = ((uint32_t)e[5 * i] << 24) | ((uint32_t)e[5 * i + 1] << 16) |
                                  ((uint32_t)e[5 * i + 2] << 8) | e[5 * i + 3];
                out->flags[i] = e[5 * i + 4];
            }
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int list_put(void *c, uint16_t list_id, const oc_sig_chan_list_t *l)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    uint8_t e[5 * OC_SIG_CHAN_MAX];
    if (blocked(s)) return -1;
    if (l->count > OC_SIG_CHAN_MAX) return done(s, NULL); /* a failed write: dooms the transaction */
    for (int i = 0; i < l->count; i++) {
        e[5 * i] = (uint8_t)(l->freq_hz[i] >> 24);
        e[5 * i + 1] = (uint8_t)(l->freq_hz[i] >> 16);
        e[5 * i + 2] = (uint8_t)(l->freq_hz[i] >> 8);
        e[5 * i + 3] = (uint8_t)l->freq_hz[i];
        e[5 * i + 4] = l->flags[i];
    }
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO chan_list(list_id, ver, entries) VALUES(?,?,?)");
    if (st != NULL) {
        b |= sqlite3_bind_int(st, 1, list_id);
        b |= sqlite3_bind_int(st, 2, l->ver);
        b |= sqlite3_bind_blob(st, 3, e, 5 * l->count, SQLITE_TRANSIENT);
    }
    return run(s, st, b);
}

/* ---- subscribers ---- */

#define SUB_COLS "number, state, tmid, activated, k_enc, opc_enc, sqn, created, updated"

/* 0, or OC_CORE_STORE_FAILED: a row that can't be read is not "none". */
static int sub_row(oc_sql_t *s, sqlite3_stmt *st, oc_core_sub_t *out)
{
    memset(out, 0, sizeof(*out));
    if (num_col(st, 0, out->number) != 0) return OC_CORE_STORE_FAILED;
    out->state = (uint8_t)sqlite3_column_int(st, 1);
    out->tmid = (uint32_t)sqlite3_column_int64(st, 2);
    out->activated = (uint8_t)sqlite3_column_int(st, 3);
    if (unseal_col(s, st, 4, "subscriber", "k", out->number, OC_SIG_NUMBER_LEN, out->k, 16) != 0 ||
        unseal_col(s, st, 5, "subscriber", "opc", out->number, OC_SIG_NUMBER_LEN, out->opc, 16) != 0) {
        oc_sig_wipe(out, sizeof(*out));
        return OC_CORE_STORE_FAILED;
    }
    out->sqn = (uint64_t)sqlite3_column_int64(st, 6);
    out->created = (uint32_t)sqlite3_column_int64(st, 7);
    out->updated = (uint32_t)sqlite3_column_int64(st, 8);
    return 0;
}

/* The lookups that tell "none" from "failed" (oc_core_store.h): a row, no
 * row, or a query that could not run (b: its binds' codes, OR-ed). */
static int sub_one(oc_sql_t *s, sqlite3_stmt *st, int b, oc_core_sub_t *out)
{
    int rc = get_step(st, b);
    if (rc == 0) rc = sub_row(s, st, out);
    sqlite3_finalize(st);
    return rc;
}

static int sub_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_sub_t *out)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    sqlite3_stmt *st = prep(s, "SELECT " SUB_COLS " FROM subscriber WHERE number = ?");
    num_text(number, t);
    int b = st != NULL ? sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT) : SQLITE_ERROR;
    return sub_one(s, st, b, out);
}

static int sub_by_tmid(void *c, uint32_t tmid, oc_core_sub_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT " SUB_COLS " FROM subscriber WHERE tmid = ? AND activated = 1");
    int b = st != NULL ? sqlite3_bind_int64(st, 1, tmid) : SQLITE_ERROR;
    return sub_one(s, st, b, out);
}

static int sub_put(void *c, const oc_core_sub_t *x)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO subscriber(" SUB_COLS ") VALUES(?,?,?,?,?,?,?,?,?)");
    if (st == NULL) return done(s, NULL);
    num_text(x->number, t);
    b |= sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
    b |= sqlite3_bind_int(st, 2, x->state);
    b |= sqlite3_bind_int64(st, 3, x->tmid);
    b |= sqlite3_bind_int(st, 4, x->activated);
    b |= seal_bind(s, st, 5, "subscriber", "k", x->number, OC_SIG_NUMBER_LEN, x->k, 16);
    b |= seal_bind(s, st, 6, "subscriber", "opc", x->number, OC_SIG_NUMBER_LEN, x->opc, 16);
    b |= sqlite3_bind_int64(st, 7, (sqlite3_int64)x->sqn);
    b |= sqlite3_bind_int64(st, 8, x->created);
    b |= sqlite3_bind_int64(st, 9, x->updated);
    return run(s, st, b);
}

/* ---- tokens ---- */

static int token_get(void *c, const uint8_t token_id[8], oc_core_token_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT number, secret_enc, expiry, used_at, used_by_tmid FROM token WHERE token_id = ?");
    int b = st != NULL ? sqlite3_bind_blob(st, 1, token_id, 8, SQLITE_TRANSIENT) : SQLITE_ERROR;
    int rc = get_step(st, b);
    memset(out, 0, sizeof(*out));
    if (rc == 0) {
        if (num_col(st, 0, out->number) != 0 ||
            unseal_col(s, st, 1, "token", "secret", token_id, 8, out->secret, 16) != 0) {
            oc_sig_wipe(out, sizeof(*out));
            rc = OC_CORE_STORE_FAILED;
        } else {
            memcpy(out->token_id, token_id, 8);
            out->expiry = (uint32_t)sqlite3_column_int64(st, 2);
            out->used_at = (uint32_t)sqlite3_column_int64(st, 3);
            out->used_by_tmid = (uint32_t)sqlite3_column_int64(st, 4);
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int token_put(void *c, const oc_core_token_t *x)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    /* an upsert on token_id only: a second unused token for a number is
     * refused (token_one_unused), never a silent replacement of the first */
    sqlite3_stmt *st = prep(s, "INSERT INTO token(token_id, number, secret_enc, expiry, used_at, used_by_tmid)"
                               " VALUES(?,?,?,?,?,?) ON CONFLICT(token_id) DO UPDATE SET number = excluded.number,"
                               " secret_enc = excluded.secret_enc, expiry = excluded.expiry,"
                               " used_at = excluded.used_at, used_by_tmid = excluded.used_by_tmid");
    if (st == NULL) return done(s, NULL);
    num_text(x->number, t);
    b |= sqlite3_bind_blob(st, 1, x->token_id, 8, SQLITE_TRANSIENT);
    b |= sqlite3_bind_text(st, 2, t, -1, SQLITE_TRANSIENT);
    b |= seal_bind(s, st, 3, "token", "secret", x->token_id, 8, x->secret, 16);
    b |= sqlite3_bind_int64(st, 4, x->expiry);
    b |= sqlite3_bind_int64(st, 5, x->used_at);
    b |= sqlite3_bind_int64(st, 6, x->used_by_tmid);
    return run(s, st, b);
}

static int by_number(oc_sql_t *s, const char *sql, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, sql);
    num_text(number, t);
    if (st != NULL) b |= sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
    return run(s, st, b);
}

static int by_int(oc_sql_t *s, const char *sql, sqlite3_int64 v)
{
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, sql);
    if (st != NULL) b |= sqlite3_bind_int64(st, 1, v);
    return run(s, st, b);
}

static int token_void(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    return by_number(S(c), "DELETE FROM token WHERE number = ? AND used_at = 0", number);
}

/* ---- issued vectors ---- */

static int av_put(void *c, const oc_core_av_issued_t *a)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO av_issued(number, rand, xres, sqn, cell_id, issued, confirmed)"
                               " VALUES(?,?,?,?,?,?,?)");
    if (st != NULL) {
        num_text(a->number, t);
        b |= sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
        b |= sqlite3_bind_blob(st, 2, a->rand, 16, SQLITE_TRANSIENT);
        b |= sqlite3_bind_blob(st, 3, a->xres, 8, SQLITE_TRANSIENT);
        b |= sqlite3_bind_int64(st, 4, (sqlite3_int64)a->sqn);
        b |= sqlite3_bind_int64(st, 5, a->cell_id);
        b |= sqlite3_bind_int64(st, 6, a->issued);
        b |= sqlite3_bind_int(st, 7, a->confirmed);
    }
    return run(s, st, b);
}

static int av_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], const uint8_t rand[16], oc_core_av_issued_t *out)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    sqlite3_stmt *st = prep(s, "SELECT xres, sqn, cell_id, issued, confirmed FROM av_issued WHERE number = ? AND rand = ?");
    num_text(number, t);
    int b = SQLITE_ERROR;
    if (st != NULL) {
        b = sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
        b |= sqlite3_bind_blob(st, 2, rand, 16, SQLITE_TRANSIENT);
    }
    int rc = get_step(st, b);
    memset(out, 0, sizeof(*out));
    if (rc == 0) {
        memcpy(out->number, number, OC_SIG_NUMBER_LEN);
        memcpy(out->rand, rand, 16);
        blob_col(st, 0, out->xres, 8);
        out->sqn = (uint64_t)sqlite3_column_int64(st, 1);
        out->cell_id = (uint32_t)sqlite3_column_int64(st, 2);
        out->issued = (uint32_t)sqlite3_column_int64(st, 3);
        out->confirmed = (uint8_t)sqlite3_column_int(st, 4);
    }
    sqlite3_finalize(st);
    return rc;
}

static int av_drop_cell(void *c, uint32_t cell_id)
{
    return by_int(S(c), "DELETE FROM av_issued WHERE cell_id = ? AND confirmed = 0", cell_id);
}

static int av_del_number(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    return by_number(S(c), "DELETE FROM av_issued WHERE number = ?", number);
}

static int av_newest_confirmed(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], uint32_t not_cell, uint64_t *sqn)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    sqlite3_stmt *st =
        prep(s, "SELECT MAX(sqn) FROM av_issued WHERE number = ? AND confirmed = 1 AND cell_id <> ?");
    num_text(number, t);
    int b = SQLITE_ERROR;
    if (st != NULL) {
        b = sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
        b |= sqlite3_bind_int64(st, 2, not_cell);
    }
    int rc = get_step(st, b); /* an aggregate: always one row, NULL when none */
    if (rc == 0) {
        if (sqlite3_column_type(st, 0) == SQLITE_NULL) {
            rc = OC_CORE_STORE_NONE;
        } else {
            *sqn = (uint64_t)sqlite3_column_int64(st, 0);
        }
    } else if (rc == OC_CORE_STORE_NONE) {
        rc = OC_CORE_STORE_FAILED;
    }
    sqlite3_finalize(st);
    return rc;
}

static int av_prune(void *c, uint32_t before) { return by_int(S(c), "DELETE FROM av_issued WHERE issued < ?", before); }

/* ---- locations ---- */

static int loc_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_loc_t *out)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    sqlite3_stmt *st = prep(s, "SELECT cell_id, tmid, expires, sqn, rand FROM location WHERE number = ?");
    num_text(number, t);
    int b = st != NULL ? sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT) : SQLITE_ERROR;
    int rc = get_step(st, b);
    memset(out, 0, sizeof(*out));
    if (rc == 0) {
        memcpy(out->number, number, OC_SIG_NUMBER_LEN);
        out->cell_id = (uint32_t)sqlite3_column_int64(st, 0);
        out->tmid = (uint32_t)sqlite3_column_int64(st, 1);
        out->expires = (uint32_t)sqlite3_column_int64(st, 2);
        out->sqn = (uint64_t)sqlite3_column_int64(st, 3);
        blob_col(st, 4, out->rand, sizeof(out->rand));
    }
    sqlite3_finalize(st);
    return rc;
}

static int loc_put(void *c, const oc_core_loc_t *l)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st =
        prep(s, "INSERT OR REPLACE INTO location(number, cell_id, tmid, expires, sqn, rand) VALUES(?,?,?,?,?,?)");
    if (st != NULL) {
        num_text(l->number, t);
        b |= sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
        b |= sqlite3_bind_int64(st, 2, l->cell_id);
        b |= sqlite3_bind_int64(st, 3, l->tmid);
        b |= sqlite3_bind_int64(st, 4, l->expires);
        b |= sqlite3_bind_int64(st, 5, (sqlite3_int64)l->sqn);
        b |= sqlite3_bind_blob(st, 6, l->rand, sizeof(l->rand), SQLITE_TRANSIENT);
    }
    return run(s, st, b);
}

/* -1 when there was none, which (unlike a delete that failed) does not doom
 * the transaction (oc_core_store.h). */
static int loc_del(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    oc_sql_t *s = S(c);
    if (by_number(s, "DELETE FROM location WHERE number = ?", number) != 0) return -1;
    return sqlite3_changes(s->db) > 0 ? 0 : -1;
}

static int loc_purge_cell(void *c, uint32_t cell_id)
{
    return by_int(S(c), "DELETE FROM location WHERE cell_id = ?", cell_id);
}

/* ---- records ---- */

static int cdr_add(void *c, const oc_core_cdr_t *x)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    char ta[OC_SIG_NUMBER_TEXT], tb[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT INTO cdr(caller, called, cell_a, cell_b, setup, answer, \"end\", cause)"
                               " VALUES(?,?,?,?,?,?,?,?)");
    if (st != NULL) {
        num_text(x->caller, ta);
        num_text(x->called, tb);
        b |= sqlite3_bind_text(st, 1, ta, -1, SQLITE_TRANSIENT);
        b |= sqlite3_bind_text(st, 2, tb, -1, SQLITE_TRANSIENT);
        b |= sqlite3_bind_int64(st, 3, x->cell_a);
        b |= sqlite3_bind_int64(st, 4, x->cell_b);
        b |= sqlite3_bind_int64(st, 5, x->setup);
        b |= sqlite3_bind_int64(st, 6, x->answer);
        b |= sqlite3_bind_int64(st, 7, x->end);
        b |= sqlite3_bind_int(st, 8, x->cause);
    }
    return run(s, st, b);
}

static int audit_add(void *c, const oc_core_audit_t *x)
{
    oc_sql_t *s = S(c);
    int b = SQLITE_OK; /* the binds' codes, OR-ed */
    static const uint8_t zero[OC_SIG_NUMBER_LEN];
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT INTO audit(ts, event, number, tmid, cell_id, detail) VALUES(?,?,?,?,?,?)");
    if (st != NULL) {
        b |= sqlite3_bind_int64(st, 1, x->ts);
        b |= sqlite3_bind_int(st, 2, x->event);
        if (memcmp(x->number, zero, OC_SIG_NUMBER_LEN) != 0) {
            num_text(x->number, t);
            b |= sqlite3_bind_text(st, 3, t, -1, SQLITE_TRANSIENT);
        }
        b |= sqlite3_bind_int64(st, 4, x->tmid);
        b |= sqlite3_bind_int64(st, 5, x->cell_id);
        b |= sqlite3_bind_text(st, 6, x->detail, (int)strnlen(x->detail, sizeof(x->detail)), SQLITE_TRANSIENT);
    }
    return run(s, st, b);
}

/* ---- open, migrate, close ---- */

static int user_version(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* The backup holds sealed keys only, but is owner-only like the database:
 * created under umask 0077 (its journal too), then checked with chmod. A
 * failed backup is removed. */
static int backup_to(sqlite3 *db, const char *path)
{
    sqlite3 *out = NULL;
    mode_t old = umask(0077);
    int ok = sqlite3_open_v2(path, &out, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK;
    sqlite3_backup *b = ok ? sqlite3_backup_init(out, "main", db, "main") : NULL;
    ok = b != NULL && sqlite3_backup_step(b, -1) == SQLITE_DONE;
    if (b != NULL && sqlite3_backup_finish(b) != SQLITE_OK) ok = 0;
    if (sqlite3_close(out) != SQLITE_OK) ok = 0;
    umask(old);
    if (ok && chmod(path, 0600) != 0) ok = 0;
    if (!ok) unlink(path);
    return ok ? 0 : -1;
}

/* The key check: KEY_CHECK sealed under the master key, in meta. */
static int key_check_put(oc_sql_t *s)
{
    int b = SQLITE_OK;
    sqlite3_stmt *st = prep(s, "INSERT INTO meta(k, v) VALUES('key_check', ?)");
    if (st != NULL) b |= seal_bind(s, st, 1, "meta", "key_check", (const uint8_t *)"", 0, (const uint8_t *)KEY_CHECK,
                                   sizeof(KEY_CHECK) - 1);
    return run(s, st, b);
}

/* The master key must open the check value of a database past v0; one
 * without a check value is refused, not given one under whatever key
 * opened it. */
static int key_check(oc_sql_t *s, const char *path, char *err, size_t cap)
{
    uint8_t pt[sizeof(KEY_CHECK) - 1];
    sqlite3_stmt *st = prep(s, "SELECT v FROM meta WHERE k = 'key_check'");
    int rc = -1, step = st != NULL ? sqlite3_step(st) : SQLITE_ERROR;
    if (step == SQLITE_ROW) {
        rc = unseal_col(s, st, 0, "meta", "key_check", (const uint8_t *)"", 0, pt, sizeof(pt)) == 0 &&
                     memcmp(pt, KEY_CHECK, sizeof(pt)) == 0
                 ? 0
                 : -1;
        if (rc != 0) snprintf(err, cap, "%s: the master key does not open this database", path);
        s->unseal_failures = 0;
        oc_sig_wipe(pt, sizeof(pt));
    } else if (step == SQLITE_DONE) {
        snprintf(err, cap, "%s: missing key check: refusing to open", path);
    } else {
        snprintf(err, cap, "%s: can't read the key check: %s", path, sqlite3_errmsg(s->db));
    }
    sqlite3_finalize(st);
    return rc;
}

/* Key check first, for a database past v0: a wrong key backs up and
 * migrates nothing. Then the backup, then each migration in its own
 * transaction; migration 0's writes the key check in the same one. */
static int migrate(oc_sql_t *s, const char *path, const char *const *mig, unsigned n, char *err, size_t cap)
{
    int v = user_version(s->db);
    if (v < 0) {
        snprintf(err, cap, "%s: can't read the schema version: %s", path, sqlite3_errmsg(s->db));
        return -1;
    }
    if ((unsigned)v > n) {
        snprintf(err, cap, "%s: schema v%d is newer than this oc-core (v%u): install a newer oc-core", path, v, n);
        return -1;
    }
    if (n == 0) {
        snprintf(err, cap, "%s: no schema to create", path);
        return -1;
    }
    if (v > 0 && key_check(s, path, err, cap) != 0) return -1;
    if ((unsigned)v == n) return 0;
    if (v > 0 && strcmp(path, ":memory:") != 0) {
        snprintf(s->backup, sizeof(s->backup), "%s.v%d.%lld.bak", path, v, (long long)time(NULL));
        if (backup_to(s->db, s->backup) != 0) {
            snprintf(err, cap, "%s: backup before migrating failed; nothing changed", s->backup);
            s->backup[0] = '\0';
            return -1;
        }
    }
    for (unsigned i = (unsigned)v; i < n; i++) {
        char pragma[48];
        snprintf(pragma, sizeof(pragma), "PRAGMA user_version = %u", i + 1u);
        char *e = NULL;
        int ok = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
                 sqlite3_exec(s->db, mig[i], NULL, NULL, &e) == SQLITE_OK && (i != 0 || key_check_put(s) == 0) &&
                 sqlite3_exec(s->db, pragma, NULL, NULL, NULL) == SQLITE_OK &&
                 sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        if (!ok) {
            snprintf(err, cap, "%s: migration to v%u failed (%s); the database stays at v%u", path, i + 1u,
                     e != NULL ? e : sqlite3_errmsg(s->db), i);
            sqlite3_free(e);
            if (!sqlite3_get_autocommit(s->db)) sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
            return -1;
        }
    }
    return 0;
}

oc_sql_t *oc_sql_open(const oc_sql_cfg_t *cfg, char *err, size_t cap)
{
    oc_sql_t *s = calloc(1, sizeof(*s));
    int mem = strcmp(cfg->path, ":memory:") == 0;
    if (s == NULL) {
        snprintf(err, cap, "out of memory");
        return NULL;
    }
    s->lock_fd = -1;
    memcpy(s->key, cfg->master_key, 32);
    s->random = cfg->random;
    if (!mem) {
        char lp[600];
        snprintf(lp, sizeof(lp), "%s.lock", cfg->path);
        s->lock_fd = open(lp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (s->lock_fd < 0) {
            snprintf(err, cap, "%s: %s", lp, strerror(errno));
            oc_sql_close(s);
            return NULL;
        }
        if (flock(s->lock_fd, LOCK_EX | LOCK_NB) != 0) {
            snprintf(err, cap, "%s is in use (oc-core is running, or another admin --offline): stop it first",
                     cfg->path);
            oc_sql_close(s);
            return NULL;
        }
    }
    mode_t old = umask(0077); /* the database and its WAL: owner only */
    int rc = sqlite3_open_v2(cfg->path, &s->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    umask(old);
    if (rc != SQLITE_OK) {
        snprintf(err, cap, "%s: %s", cfg->path, s->db != NULL ? sqlite3_errmsg(s->db) : "can't open");
        oc_sql_close(s);
        return NULL;
    }
    /* The lock keeps other oc-core processes out, so the only other
     * connections are outside readers (sqlite3 on the database, a backup
     * tool); in WAL mode they never block a write for long, and 2 s covers
     * a checkpoint they hold up. */
    sqlite3_busy_timeout(s->db, 2000);
    /* journal_mode answers with the mode it got: anything but WAL (":memory:"
     * has only "memory") is refused rather than run without it */
    char mode[16] = "";
    sqlite3_stmt *jm = prep(s, "PRAGMA journal_mode = WAL");
    if (jm != NULL && sqlite3_step(jm) == SQLITE_ROW && sqlite3_column_text(jm, 0) != NULL) {
        snprintf(mode, sizeof(mode), "%s", (const char *)sqlite3_column_text(jm, 0));
    }
    sqlite3_finalize(jm);
    if (strcmp(mode, mem ? "memory" : "wal") != 0) {
        snprintf(err, cap, "%s: can't use WAL (journal mode \"%s\"): %s", cfg->path, mode, sqlite3_errmsg(s->db));
        oc_sql_close(s);
        return NULL;
    }
    if (sqlite3_exec(s->db, "PRAGMA synchronous = FULL", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(err, cap, "%s: %s", cfg->path, sqlite3_errmsg(s->db));
        oc_sql_close(s);
        return NULL;
    }
    const char *const *mig = cfg->migrations != NULL ? cfg->migrations : MIGRATIONS;
    unsigned n = cfg->migrations != NULL ? cfg->nmigrations : (unsigned)(sizeof(MIGRATIONS) / sizeof(MIGRATIONS[0]));
    if (migrate(s, cfg->path, mig, n, err, cap) != 0) {
        oc_sql_close(s);
        return NULL;
    }
    return s;
}

void oc_sql_close(oc_sql_t *s)
{
    if (s == NULL) return;
    if (s->db != NULL) sqlite3_close_v2(s->db); /* every statement is finalized where it is used */
    if (s->lock_fd >= 0) close(s->lock_fd); /* drops the lock */
    oc_sig_wipe(s->key, sizeof(s->key));
    free(s);
}

const char *oc_sql_migration(unsigned i)
{
    return i < sizeof(MIGRATIONS) / sizeof(MIGRATIONS[0]) ? MIGRATIONS[i] : NULL;
}

sqlite3 *oc_sql_db(oc_sql_t *s) { return s->db; }
int oc_sql_version(oc_sql_t *s) { return user_version(s->db); }
const char *oc_sql_backup(oc_sql_t *s) { return s->backup; }
unsigned oc_sql_unseal_failures(oc_sql_t *s) { return s->unseal_failures; }

oc_core_store_t oc_sql_store(oc_sql_t *s)
{
    oc_core_store_t st = {
        .ctx = s,
        .begin = begin,
        .commit = commit,
        .netkey_get = netkey_get,
        .netkey_put = netkey_put,
        .cell_get = cell_get,
        .cell_put = cell_put,
        .list_get = list_get,
        .list_put = list_put,
        .sub_get = sub_get,
        .sub_by_tmid = sub_by_tmid,
        .sub_put = sub_put,
        .token_get = token_get,
        .token_put = token_put,
        .token_void = token_void,
        .av_put = av_put,
        .av_get = av_get,
        .av_drop_cell = av_drop_cell,
        .av_del_number = av_del_number,
        .av_newest_confirmed = av_newest_confirmed,
        .av_prune = av_prune,
        .loc_get = loc_get,
        .loc_put = loc_put,
        .loc_del = loc_del,
        .loc_purge_cell = loc_purge_cell,
        .cdr_add = cdr_add,
        .audit_add = audit_add,
    };
    return st;
}
