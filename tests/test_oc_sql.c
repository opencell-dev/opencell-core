#define _GNU_SOURCE
/* The SQLite store (network-core spec §5, §9.1, §17 decision 9): the store
 * contract, keys sealed at rest, the master-key check, the lock, the
 * schema migrations and their backup, and transactions that fail whole. */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core_store_contract.h"
#include "oc_core.h"
#include "oc_sql.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t KEY[32] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                                 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                                 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F };
static uint32_t rng = 7;
static void rnd(uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((rng = rng * 1103515245u + 12345u) >> 16);
}

static char dir[64], db[96];

static oc_sql_t *open_db(const char *path, const uint8_t *key, const char *const *mig, unsigned n, char *err)
{
    oc_sql_cfg_t cfg = { path, key, rnd, mig, n };
    return oc_sql_open(&cfg, err, 256);
}

static void fresh_dir(void)
{
    strcpy(dir, "/tmp/oc_sql_test_XXXXXX");
    TEST_ASSERT_NOT_NULL(mkdtemp(dir));
    snprintf(db, sizeof(db), "%s/core.db", dir);
}

static void rm_dir(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    TEST_ASSERT_EQUAL_INT(0, system(cmd));
}

static void test_sql_store_keeps_the_contract(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    store_contract(&st);
    TEST_ASSERT_EQUAL_INT(OC_SQL_VERSION, oc_sql_version(s));
    oc_sql_close(s);
}

/* True if the file holds these bytes anywhere; the file must exist (a
 * search of a missing file would pass whatever was on disk). Searched
 * in-process: `grep -P '\xC1{16}'` under a UTF-8 locale never matches a
 * raw byte, so a shell search would pass whatever the file held. */
static int file_has(const char *path, const uint8_t *pat, size_t n)
{
    FILE *f = fopen(path, "rb");
    TEST_ASSERT_NOT_NULL_MESSAGE(f, path);
    static uint8_t buf[1 << 20];
    size_t len = fread(buf, 1, sizeof(buf), f);
    TEST_ASSERT_TRUE_MESSAGE(feof(f), "test file larger than the search buffer");
    fclose(f);
    return memmem(buf, len, pat, n) != NULL;
}

static oc_core_sub_t a_sub(void)
{
    oc_core_sub_t x;
    memset(&x, 0, sizeof(x));
    contract_num("+883160655501234", x.number);
    x.state = OC_CORE_SUB_ACTIVE;
    x.activated = 1;
    x.tmid = 0x76AD0488u;
    memset(x.k, 0xC1, 16);
    memset(x.opc, 0xC2, 16);
    x.sqn = 41;
    return x;
}

/* K and OPc are never in the file in the clear, and come back after a
 * restart; a file-level search for their bytes finds nothing. */
static void test_keys_are_sealed_on_disk_and_survive_a_restart(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(s), "SELECT k_enc FROM subscriber", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    TEST_ASSERT_EQUAL_INT(16 + 29, sqlite3_column_bytes(q, 0));
    TEST_ASSERT_TRUE(memcmp((const uint8_t *)sqlite3_column_blob(q, 0) + 13, x.k, 16) != 0);
    sqlite3_finalize(q);

    /* while the store is open the row is in the WAL (closing checkpoints
     * it into the database and deletes the WAL) */
    char wal[128];
    struct stat sb;
    snprintf(wal, sizeof(wal), "%s-wal", db);
    TEST_ASSERT_EQUAL_INT(0, stat(wal, &sb));
    TEST_ASSERT_EQUAL_UINT(0600, sb.st_mode & 0777);
    /* numbers are in the clear: the search works */
    TEST_ASSERT_TRUE(file_has(wal, (const uint8_t *)"+883160655501234", 16));
    TEST_ASSERT_FALSE(file_has(wal, x.k, 16));
    TEST_ASSERT_FALSE(file_has(wal, x.opc, 16));
    oc_sql_close(s);

    TEST_ASSERT_TRUE(file_has(db, (const uint8_t *)"+883160655501234", 16));
    TEST_ASSERT_FALSE(file_has(db, x.k, 16));
    TEST_ASSERT_FALSE(file_has(db, x.opc, 16));
    TEST_ASSERT_EQUAL_INT(0, stat(db, &sb));
    TEST_ASSERT_EQUAL_UINT(0600, sb.st_mode & 0777);

    s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    st = oc_sql_store(s);
    TEST_ASSERT_EQUAL_INT(0, st.sub_by_tmid(st.ctx, 0x76AD0488u, &y));
    TEST_ASSERT_EQUAL_MEMORY(x.k, y.k, 16);
    TEST_ASSERT_EQUAL_MEMORY(x.opc, y.opc, 16);
    TEST_ASSERT_EQUAL_UINT64(41, y.sqn);
    oc_sql_close(s);
    rm_dir();
}

static void test_a_wrong_master_key_is_refused_at_open(void)
{
    char err[256];
    uint8_t other[32];
    memcpy(other, KEY, 32);
    other[31] ^= 0x80;
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_sql_close(s);
    TEST_ASSERT_NULL(open_db(db, other, NULL, 0, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "the master key does not open this database"));
    rm_dir();
}

/* Nothing is tried under a wrong key: a database that needs a migration is
 * neither backed up nor migrated before the key is checked. */
static void test_a_wrong_key_migrates_nothing(void)
{
    char err[256];
    uint8_t other[32];
    memcpy(other, KEY, 32);
    other[0] ^= 1;
    const char *v1[] = { oc_sql_migration(0) };
    const char *v2[] = { oc_sql_migration(0), "ALTER TABLE cell ADD COLUMN note TEXT" };
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_sql_close(s);
    TEST_ASSERT_NULL(open_db(db, other, v2, 2, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "the master key does not open this database"));
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "ls %s | grep -q 'core.db.v1.'", dir);
    TEST_ASSERT_NOT_EQUAL_INT(0, system(cmd)); /* no backup taken */
    s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(1, oc_sql_version(s)); /* not migrated */
    oc_sql_close(s);
    rm_dir();
}

/* A database past v0 without its key check is refused, not given a new one
 * under whatever key opened it. */
static void test_a_missing_key_check_is_refused(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "DELETE FROM meta WHERE k = 'key_check'", NULL, NULL,
                                                  NULL));
    oc_sql_close(s);
    TEST_ASSERT_NULL(open_db(db, KEY, NULL, 0, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "missing key check: refusing to open"));
    rm_dir();
}

/* The key check is written in migration 0's transaction: if it can't be
 * written, the database stays at v0 (and is set up afresh next time). */
static void test_the_key_check_is_written_with_the_first_migration(void)
{
    char err[256];
    const char *bad[] = { "CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL CHECK (length(v) < 10))" };
    fresh_dir();
    TEST_ASSERT_NULL(open_db(db, KEY, bad, 1, err));
    sqlite3 *raw;
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_open(db, &raw));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(raw, "PRAGMA user_version", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    TEST_ASSERT_EQUAL_INT(0, sqlite3_column_int(q, 0));
    sqlite3_finalize(q);
    sqlite3_close(raw);
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err); /* the real schema, from v0 */
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(1, oc_sql_version(s));
    oc_sql_close(s);
    rm_dir();
}

/* One process at a time: the running daemon, or one admin --offline. */
static void test_the_lock_keeps_a_second_process_out(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_NULL(open_db(db, KEY, NULL, 0, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "is in use (oc-core is running"));
    oc_sql_close(s);
    s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_sql_close(s);
    rm_dir();
}

/* §17 decision 9: a newer build migrates after a backup that still opens
 * at the old version; an older build refuses a newer database. */
static void test_migration_backs_up_first(void)
{
    char err[256];
    const char *v1[] = { oc_sql_migration(0) };
    const char *v2[] = { oc_sql_migration(0), "ALTER TABLE cell ADD COLUMN note TEXT" };
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_STRING("", oc_sql_backup(s)); /* a new database: nothing to keep */
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    oc_sql_close(s);

    s = open_db(db, KEY, v2, 2, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(2, oc_sql_version(s));
    char backup[600];
    snprintf(backup, sizeof(backup), "%s", oc_sql_backup(s));
    TEST_ASSERT_NOT_NULL(strstr(backup, "core.db.v1."));
    struct stat sb;
    TEST_ASSERT_EQUAL_INT(0, stat(backup, &sb));
    TEST_ASSERT_EQUAL_UINT(0600, sb.st_mode & 0777);
    oc_sql_close(s);

    s = open_db(backup, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(1, oc_sql_version(s));
    st = oc_sql_store(s);
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, x.number, &y));
    oc_sql_close(s);

    TEST_ASSERT_NULL(open_db(db, KEY, v1, 1, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "schema v2 is newer than this oc-core (v1)"));
    rm_dir();
}

/* A migration that fails leaves the database as it was. */
static void test_a_failed_migration_changes_nothing(void)
{
    char err[256];
    const char *v1[] = { oc_sql_migration(0) };
    const char *bad[] = { oc_sql_migration(0), "CREATE TABLE ok(x); CREATE TABLE cell(x)" };
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_sql_close(s);
    TEST_ASSERT_NULL(open_db(db, KEY, bad, 2, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "migration to v2 failed"));
    s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(1, oc_sql_version(s));
    TEST_ASSERT_EQUAL_INT(SQLITE_ERROR, sqlite3_exec(oc_sql_db(s), "SELECT * FROM ok", NULL, NULL, NULL));
    oc_sql_close(s);
    rm_dir();
}

/* oc_core commits without checking each put: a put that fails inside the
 * transaction must make the whole change fail. */
static void test_a_failed_put_fails_the_whole_transaction(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    oc_core_token_t t1, t2, tg;
    memset(&t1, 0, sizeof(t1));
    memcpy(t1.number, x.number, OC_SIG_NUMBER_LEN);
    memset(t1.token_id, 1, 8);
    t2 = t1;
    memset(t2.token_id, 2, 8);
    oc_core_loc_t l = { { 0 }, 1, x.tmid, 5000, 0, { 0 } }, lg;
    memcpy(l.number, x.number, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(0, st.token_put(st.ctx, &t1));
    TEST_ASSERT_EQUAL_INT(-1, st.token_put(st.ctx, &t2)); /* a second unused token for the number */
    TEST_ASSERT_EQUAL_INT(-1, st.loc_put(st.ctx, &l));    /* nothing more is written */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(-1, st.token_get(st.ctx, t1.token_id, &tg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.loc_get(st.ctx, x.number, &lg));

    /* a begin inside an open transaction fails and dooms it (oc_core_store.h) */
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(-1, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(-1, st.loc_put(st.ctx, &l)); /* refused */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.sub_get(st.ctx, x.number, &y));

    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x)); /* the store works on */
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx)); /* commit without begin */
    oc_sql_close(s);
}

/* SQLite may roll a transaction back by itself (SQLITE_FULL, SQLITE_IOERR,
 * SQLITE_NOMEM, SQLITE_BUSY); the statements after it would then run in
 * autocommit, each durable. The store notices, writes nothing more, and the
 * commit fails. */
static void test_a_transaction_sqlite_dropped_writes_nothing_more(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    oc_core_loc_t l = { { 0 }, 1, x.tmid, 5000, 0, { 0 } }, lg;
    memcpy(l.number, x.number, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    /* what SQLite does after an SQLITE_FULL or SQLITE_IOERR */
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "ROLLBACK", NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, st.loc_put(st.ctx, &l));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.loc_get(st.ctx, x.number, &lg)); /* not written in autocommit */
    TEST_ASSERT_EQUAL_INT(0, st.loc_put(st.ctx, &l)); /* outside a transaction: works */
    oc_sql_close(s);
}

/* A begin that fails (here: another connection holds the write lock) dooms
 * the transaction it was to open: every write until the commit is refused,
 * the commit fails, and the begin after it starts afresh. */
static void test_a_failed_begin_dooms_the_transaction(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    sqlite3 *other;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_open(db, &other));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(other, "BEGIN IMMEDIATE", NULL, NULL, NULL));
    sqlite3_busy_timeout(oc_sql_db(s), 10);
    TEST_ASSERT_EQUAL_INT(-1, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(other, "COMMIT", NULL, NULL, NULL)); /* the lock is free again */
    TEST_ASSERT_EQUAL_INT(-1, st.sub_put(st.ctx, &x));                                 /* ...but still refused */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(0, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, x.number, &y));
    sqlite3_close(other);
    oc_sql_close(s);
    rm_dir();
}

/* Lookups tell "none" from "failed" (oc_core_store.h): a row whose keys do
 * not open, or a query that can't run, is FAILED, never read as missing.
 * A delete that fails for a real reason dooms its transaction. */
static void test_a_lookup_that_fails_is_not_none(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    oc_core_loc_t lg;
    uint64_t top;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_UINT(0, oc_sql_unseal_failures(s));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "UPDATE subscriber SET k_enc = zeroblob(45)", NULL,
                                                  NULL, NULL));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.sub_by_tmid(st.ctx, x.tmid, &y));
    TEST_ASSERT_EQUAL_UINT(2, oc_sql_unseal_failures(s));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.sub_by_tmid(st.ctx, x.tmid + 1, &y));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.loc_get(st.ctx, x.number, &lg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.av_newest_confirmed(st.ctx, x.number, 0, &top));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "DROP TABLE location; DROP TABLE av_issued", NULL,
                                                  NULL, NULL));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.loc_get(st.ctx, x.number, &lg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.av_newest_confirmed(st.ctx, x.number, 0, &top));

    x = a_sub();
    contract_num("+883160655501235", x.number);
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(-1, st.loc_del(st.ctx, x.number)); /* failed, not "nothing to delete" */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.sub_get(st.ctx, x.number, &y));
    oc_sql_close(s);
}

/* A write outside begin/commit is durable when it returns (oc_core_store.h):
 * if the connection is inside a transaction the store did not open (one a
 * failed ROLLBACK left behind, say), the write is refused, since it would
 * only land if someone committed that transaction. */
static void test_a_write_outside_a_transaction_must_be_durable(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub();
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "BEGIN", NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "ROLLBACK", NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    oc_sql_close(s);
}

/* A channel list too long to store is a failed write: it dooms the
 * transaction like any other. */
static void test_an_oversized_list_dooms_the_transaction(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    oc_sig_chan_list_t l;
    memset(&l, 0, sizeof(l));
    l.count = OC_SIG_CHAN_MAX + 1u;
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(-1, st.list_put(st.ctx, 1, &l));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.sub_get(st.ctx, x.number, &y));
    oc_sql_close(s);
}

/* A value that can't be bound is a failed write, not a NULL in its column
 * (audit.number is nullable: an unbound number would pass as "none"). */
static void test_a_failed_bind_fails_the_write(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_audit_t au;
    memset(&au, 0, sizeof(au));
    contract_num("+883160655501234", au.number);
    sqlite3_limit(oc_sql_db(s), SQLITE_LIMIT_LENGTH, 15); /* the number's 16 characters no longer fit */
    TEST_ASSERT_EQUAL_INT(-1, st.audit_add(st.ctx, &au));
    sqlite3_limit(oc_sql_db(s), SQLITE_LIMIT_LENGTH, 1000000);
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(s), "SELECT count(*) FROM audit", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    TEST_ASSERT_EQUAL_INT(0, sqlite3_column_int(q, 0));
    sqlite3_finalize(q);
    oc_sql_close(s);
}

/* Every get is three-way (oc_core_store.h): a sealed value that does not
 * open, a query that can't run, or a key that can't be bound is FAILED. */
static void test_every_get_tells_failed_from_none(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    sqlite3 *d = oc_sql_db(s);
    oc_core_netkey_t k = { 1, { 1 }, { 2 }, 1800, 100 }, kg;
    oc_core_cell_t cell, cg;
    oc_sig_chan_list_t cl, clg;
    oc_core_token_t t, tg;
    oc_core_av_issued_t a, ag;
    oc_core_sub_t x = a_sub(), y;
    oc_core_loc_t lg;
    uint64_t top;
    memset(&cell, 0, sizeof(cell));
    cell.cell_id = 7;
    strcpy(cell.name, "A");
    memset(&cl, 0, sizeof(cl));
    memset(&t, 0, sizeof(t));
    memcpy(t.number, x.number, OC_SIG_NUMBER_LEN);
    memset(t.token_id, 3, 8);
    memset(&a, 0, sizeof(a));
    memcpy(a.number, x.number, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st.netkey_put(st.ctx, &k));
    TEST_ASSERT_EQUAL_INT(0, st.cell_put(st.ctx, &cell));
    TEST_ASSERT_EQUAL_INT(0, st.list_put(st.ctx, 1, &cl));
    TEST_ASSERT_EQUAL_INT(0, st.token_put(st.ctx, &t));
    TEST_ASSERT_EQUAL_INT(0, st.av_put(st.ctx, &a));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.netkey_get(st.ctx, 2, &kg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.cell_get(st.ctx, 8, &cg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.list_get(st.ctx, 2, &clg));

    /* sealed values that don't open */
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(d, "UPDATE network SET sk_enc = zeroblob(61);"
                                                     "UPDATE token SET secret_enc = zeroblob(45)", NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.netkey_get(st.ctx, 1, &kg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.token_get(st.ctx, t.token_id, &tg));
    TEST_ASSERT_EQUAL_UINT(2, oc_sql_unseal_failures(s));

    /* a key that can't be bound: not "no such row" */
    sqlite3_limit(d, SQLITE_LIMIT_LENGTH, 15);
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.loc_get(st.ctx, x.number, &lg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.av_get(st.ctx, a.number, a.rand, &ag));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.av_newest_confirmed(st.ctx, x.number, 0, &top));
    sqlite3_limit(d, SQLITE_LIMIT_LENGTH, 1000000);
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, x.number, &y));

    /* queries that can't run */
    uint8_t lv = 0;
    TEST_ASSERT_EQUAL_INT(0, st.list_ver_get(st.ctx, 1, &lv));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(d, "DROP TABLE cell; DROP TABLE chan_list; DROP TABLE network;"
                                                     "DROP TABLE token; DROP TABLE av_issued;"
                                                     "DROP TABLE chan_list_ver", NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.list_ver_get(st.ctx, 1, &lv));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.netkey_get(st.ctx, 1, &kg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.cell_get(st.ctx, 7, &cg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.list_get(st.ctx, 1, &clg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.token_get(st.ctx, t.token_id, &tg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.av_get(st.ctx, a.number, a.rand, &ag));
    oc_sql_close(s);
}

/* A fixed-size blob of the wrong size (a row oc_sql never wrote) is a
 * failed read, not zeros: a zero XRES or RAND would pass for a value. */
static void test_a_wrong_sized_blob_is_a_failed_read(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_netkey_t k = { 1, { 1 }, { 2 }, 1800, 100 }, kg;
    oc_core_sub_t x = a_sub();
    oc_core_av_issued_t a, ag;
    oc_core_loc_t l = { { 0 }, 1, x.tmid, 5000, 7, { 9 } }, lg;
    memset(&a, 0, sizeof(a));
    memcpy(a.number, x.number, OC_SIG_NUMBER_LEN);
    memcpy(l.number, x.number, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st.netkey_put(st.ctx, &k));
    TEST_ASSERT_EQUAL_INT(0, st.av_put(st.ctx, &a));
    TEST_ASSERT_EQUAL_INT(0, st.loc_put(st.ctx, &l));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "UPDATE network SET pk = zeroblob(31);"
                                                                "UPDATE av_issued SET xres = zeroblob(7);"
                                                                "UPDATE location SET rand = zeroblob(15)",
                                                  NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.netkey_get(st.ctx, 1, &kg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.av_get(st.ctx, a.number, a.rand, &ag));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.loc_get(st.ctx, x.number, &lg));
    oc_sql_close(s);
}

/* The last version written for a list is kept apart from the list's row:
 * a malformed row does not take it along (the core's repair needs it). */
static void test_the_last_list_version_outlives_a_malformed_row(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_sig_chan_list_t l, got;
    memset(&l, 0, sizeof(l));
    l.count = 1;
    l.ver = 7;
    TEST_ASSERT_EQUAL_INT(0, st.list_put(st.ctx, 5, &l));
    l.ver = 8;
    TEST_ASSERT_EQUAL_INT(0, st.list_put(st.ctx, 5, &l));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "UPDATE chan_list SET entries = zeroblob(3), ver = 1",
                                                  NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_FAILED, st.list_get(st.ctx, 5, &got));
    uint8_t ver = 0;
    TEST_ASSERT_EQUAL_INT(0, st.list_ver_get(st.ctx, 5, &ver));
    TEST_ASSERT_EQUAL_UINT8(8, ver);
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.list_ver_get(st.ctx, 6, &ver));
    oc_sql_close(s);
}

/* A transaction left open on the connection (both ROLLBACKs failed, say)
 * is rolled back by the next begin, so the store recovers without a
 * restart: nothing of the leftover lands. */
static void test_begin_clears_a_leftover_transaction(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "BEGIN; INSERT INTO cell(cell_id, name, mode, enabled)"
                                                                " VALUES(9, 'left', 0, 1)", NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(0, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, x.number, &y));
    oc_core_cell_t c;
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st.cell_get(st.ctx, 9, &c));
    oc_sql_close(s);
}

/* The database fills up in the middle of a transaction (SQLITE_FULL, here
 * by a page limit): that put fails, every later write is refused, and none
 * of the transaction is left. */
static void test_a_full_database_undoes_the_transaction(void)
{
    char err[256], sql[64];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(s), "PRAGMA page_count", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    snprintf(sql, sizeof(sql), "PRAGMA max_page_count = %d", sqlite3_column_int(q, 0) + 2);
    sqlite3_finalize(q);
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), sql, NULL, NULL, NULL));
    oc_core_sub_t x = a_sub();
    oc_core_audit_t au;
    memset(&au, 0, sizeof(au));
    int failed_at = -1;
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    for (int i = 0; i < 5000 && failed_at < 0; i++) {
        char t[32];
        snprintf(t, sizeof(t), "+88316065551%04d", i);
        contract_num(t, x.number);
        if (st.sub_put(st.ctx, &x) != 0) failed_at = i;
    }
    TEST_ASSERT_TRUE_MESSAGE(failed_at > 0, "the page limit was never reached");
    TEST_ASSERT_EQUAL_INT(-1, st.audit_add(st.ctx, &au)); /* doomed: nothing more */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(s), "SELECT count(*) FROM subscriber", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    TEST_ASSERT_EQUAL_INT(0, sqlite3_column_int(q, 0));
    sqlite3_finalize(q);
    oc_sql_close(s);
}

/* The core over this store: a vector's SQN is on disk when AV_RES leaves,
 * and a restarted core carries on above it (§9.1 "SQN monotonic across
 * restarts"). */
static oc_core_msg_t last;
static int k_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    (void)link;
    last = *m;
    return 0;
}
static uint32_t k_unix(void *c)
{
    (void)c;
    return 1790000000u;
}
static void k_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    rnd(out, n);
}

static uint64_t ask_one_vector(oc_sql_t *s, int first)
{
    static oc_core_t k;
    oc_core_route_t rt;
    oc_core_cfg_t cfg;
    const oc_core_io_t io = { NULL, k_send, NULL, k_random, k_unix, NULL };
    oc_core_store_t st = oc_sql_store(s);
    oc_core_route_init(&rt, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&rt, "8831606", 1, 1));
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    contract_num("+883160655500100", cfg.echo_number);
    if (first) {
        uint8_t r[32];
        rnd(r, 32);
        TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&st, 1, 1800, r, 1790000000u));
    }
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&k, &io, &st, &rt, &cfg));
    if (first) {
        TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&k, 1, "bench", OC_SIG_MODE_PART15, 0));
        oc_core_sub_t x = a_sub();
        TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    }
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    oc_core_link_up(&k, 5, 1000);
    m.type = OC_CORE_HELLO;
    m.u.hello.proto = OC_CORE_PROTO;
    m.u.hello.cell_id = 1;
    m.u.hello.boot_id = 99;
    oc_core_rx(&k, 5, &m, 1000);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_HELLO_ACK, last.type);
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_AV_REQ;
    m.u.av_req.tmid = 0x76AD0488u;
    m.u.av_req.count = 1;
    oc_core_rx(&k, 5, &m, 2000);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_AV_RES, last.type);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_AV_OK, last.u.av_res.status);
    oc_core_sub_t y;
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, last.u.av_res.number, &y));
    return y.sqn;
}

static void test_sqn_rises_across_a_core_restart(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_UINT64(42, ask_one_vector(s, 1));
    oc_sql_close(s);
    s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_UINT64(43, ask_one_vector(s, 0));
    oc_sql_close(s);
    rm_dir();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sql_store_keeps_the_contract);
    RUN_TEST(test_keys_are_sealed_on_disk_and_survive_a_restart);
    RUN_TEST(test_a_wrong_master_key_is_refused_at_open);
    RUN_TEST(test_a_wrong_key_migrates_nothing);
    RUN_TEST(test_a_missing_key_check_is_refused);
    RUN_TEST(test_the_key_check_is_written_with_the_first_migration);
    RUN_TEST(test_the_lock_keeps_a_second_process_out);
    RUN_TEST(test_migration_backs_up_first);
    RUN_TEST(test_a_failed_migration_changes_nothing);
    RUN_TEST(test_a_failed_put_fails_the_whole_transaction);
    RUN_TEST(test_a_transaction_sqlite_dropped_writes_nothing_more);
    RUN_TEST(test_a_full_database_undoes_the_transaction);
    RUN_TEST(test_a_write_outside_a_transaction_must_be_durable);
    RUN_TEST(test_an_oversized_list_dooms_the_transaction);
    RUN_TEST(test_a_failed_bind_fails_the_write);
    RUN_TEST(test_a_failed_begin_dooms_the_transaction);
    RUN_TEST(test_a_lookup_that_fails_is_not_none);
    RUN_TEST(test_every_get_tells_failed_from_none);
    RUN_TEST(test_a_wrong_sized_blob_is_a_failed_read);
    RUN_TEST(test_begin_clears_a_leftover_transaction);
    RUN_TEST(test_the_last_list_version_outlives_a_malformed_row);
    RUN_TEST(test_sqn_rises_across_a_core_restart);
    return UNITY_END();
}
