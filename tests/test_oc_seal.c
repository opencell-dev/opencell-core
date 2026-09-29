#define _GNU_SOURCE
/* oc_seal (network-core spec §5, §9.1 "AES-GCM seal/open, including a wrong
 * AAD") and the master key file. */
#include "unity.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oc_seal.h"

/* Every test gets a fresh, empty temp directory for any files it creates
 * (key files, a FIFO, ...), removed in tearDown so nothing lingers even
 * when a TEST_ASSERT in the middle of a test aborts it (Unity longjmps back
 * to the runner, which still calls tearDown next). */
static char g_dir_tmpl[] = "/tmp/oc_seal_test_XXXXXX";
static char g_dir[sizeof(g_dir_tmpl)];

static void rm_dir_contents(const char *dir)
{
    DIR *d = opendir(dir);
    if (d == NULL) return;
    struct dirent *e;
    char p[600];
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        unlink(p);
    }
    closedir(d);
}

void setUp(void)
{
    memcpy(g_dir, g_dir_tmpl, sizeof(g_dir_tmpl));
    TEST_ASSERT_NOT_NULL(mkdtemp(g_dir));
}

void tearDown(void)
{
    rm_dir_contents(g_dir);
    rmdir(g_dir);
}

static const uint8_t KEY[32] = { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const uint8_t NONCE[12] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB };
static const uint8_t PK[8] = { 0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x4F };

static void test_seal_opens_with_the_same_row(void)
{
    uint8_t k[16], blob[16 + OC_SEAL_OVERHEAD], back[16];
    memset(k, 0x5A, 16);
    TEST_ASSERT_EQUAL_INT(0, oc_seal(KEY, "subscriber", "k", PK, 8, k, 16, NONCE, blob));
    TEST_ASSERT_EQUAL_UINT8(OC_SEAL_VERSION, blob[0]);
    TEST_ASSERT_EQUAL_MEMORY(NONCE, blob + 1, 12);
    TEST_ASSERT_TRUE(memcmp(blob + 13, k, 16) != 0); /* not in the clear */
    TEST_ASSERT_EQUAL_INT(0, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_MEMORY(k, back, 16);
}

/* A blob moved to another column, row or table, or opened with another key,
 * or changed in one bit, does not open. */
static void test_seal_refuses_anything_else(void)
{
    uint8_t k[16], blob[16 + OC_SEAL_OVERHEAD], back[16], pk2[8], key2[32];
    memset(k, 0x5A, 16);
    memcpy(pk2, PK, 8);
    pk2[7] ^= 0x10;
    memcpy(key2, KEY, 32);
    key2[0] ^= 1;
    TEST_ASSERT_EQUAL_INT(0, oc_seal(KEY, "subscriber", "k", PK, 8, k, 16, NONCE, blob));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "opc", PK, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "k", pk2, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "token", "k", PK, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(key2, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
    for (size_t i = 0; i < sizeof(blob); i++) {
        blob[i] ^= 0x01;
        TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
        blob[i] ^= 0x01;
    }
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob) - 1, back));
    TEST_ASSERT_EQUAL_INT(0, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
}

/* The AAD's fields are separated, so "ab"+"c" is not "a"+"bc". */
static void test_aad_fields_do_not_run_together(void)
{
    uint8_t s[8] = { 7 }, blob[8 + OC_SEAL_OVERHEAD], back[8];
    TEST_ASSERT_EQUAL_INT(0, oc_seal(KEY, "ab", "c", PK, 8, s, 8, NONCE, blob));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "a", "bc", PK, 8, blob, sizeof(blob), back));
}

/* A failed unseal must not write anything into the caller's plaintext
 * buffer: a caller that forgot to check the return value must not read a
 * partial or spoofed secret. */
static void test_failed_unseal_leaves_pt_untouched(void)
{
    uint8_t k[16], blob[16 + OC_SEAL_OVERHEAD], back[16], key2[32], untouched[16];
    memset(k, 0x5A, 16);
    memcpy(key2, KEY, 32);
    key2[0] ^= 1;
    memset(back, 0xEE, sizeof(back));
    memset(untouched, 0xEE, sizeof(untouched));
    TEST_ASSERT_EQUAL_INT(0, oc_seal(KEY, "subscriber", "k", PK, 8, k, 16, NONCE, blob));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(key2, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_MEMORY(untouched, back, sizeof(back));
}

/* n above OC_SEAL_PT_MAX is refused outright, not truncated or partially
 * sealed. */
static void test_seal_refuses_n_over_max(void)
{
    uint8_t pt[OC_SEAL_PT_MAX + 1], out[OC_SEAL_PT_MAX + 1 + OC_SEAL_OVERHEAD];
    memset(pt, 0x11, sizeof(pt));
    TEST_ASSERT_EQUAL_INT(-1, oc_seal(KEY, "subscriber", "k", PK, 8, pt, sizeof(pt), NONCE, out));
}

/* The AAD builder bounds each of table/column/pk_n before summing, so a
 * huge pk_n can't wrap the size_t sum back under AAD_MAX and slip a memcpy
 * of pk_n bytes past a 128-byte stack buffer. table "subscriber" (11) +
 * column "k" (2) + huge + 1 wraps to 0 (mod 2^64) without the per-field
 * check, which a naive "> AAD_MAX" test would accept. With the fix in
 * place this is safe to run (pk is never read at that length, since the
 * per-field bound rejects it first); it is not safe to run against the
 * unfixed code (it would smash the stack), so this is implement-then-test
 * rather than red-first. */
static void test_seal_aad_pk_n_cannot_wrap(void)
{
    uint8_t k[16], blob[16 + OC_SEAL_OVERHEAD];
    memset(k, 0x5A, 16);
    size_t huge = (size_t)-14;
    TEST_ASSERT_EQUAL_INT(-1, oc_seal(KEY, "subscriber", "k", PK, huge, k, 16, NONCE, blob));
}

static void write_key(const char *path, size_t n, mode_t mode)
{
    unlink(path); /* the last one may be read-only */
    FILE *f = fopen(path, "w");
    TEST_ASSERT_NOT_NULL(f);
    for (size_t i = 0; i < n; i++) fputc((int)(i + 1), f);
    fclose(f);
    TEST_ASSERT_EQUAL_INT(0, chmod(path, mode));
}

static void test_key_file_rules(void)
{
    char path[300], err[160];
    uint8_t k[32];
    snprintf(path, sizeof(path), "%s/key", g_dir);

    write_key(path, 32, 0400);
    TEST_ASSERT_EQUAL_INT(0, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_EQUAL_MEMORY(KEY, k, 32);

    write_key(path, 32, 0640);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "accessible by group or others (mode 640)"));

    write_key(path, 31, 0600);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "exactly 32 bytes"));

    write_key(path, 33, 0600);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "exactly 32 bytes"));

    unlink(path);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "No such file"));
}

/* A FIFO must be refused, and refused promptly: a blocking open() (no
 * writer on the other end) would hang the daemon at startup. This is the
 * test that proves the O_NONBLOCK added to oc_key_load's open() — without
 * it, this test would hang rather than fail. */
static void test_key_file_refuses_fifo(void)
{
    char path[300], err[160];
    uint8_t k[32];
    snprintf(path, sizeof(path), "%s/fifo", g_dir);
    TEST_ASSERT_EQUAL_INT(0, mkfifo(path, 0600));
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "not a regular file"));
}

/* A directory is refused the same way. */
static void test_key_file_refuses_directory(void)
{
    char err[160];
    uint8_t k[32];
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(g_dir, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "not a regular file"));
}

/* The ownership check (file must be owned by the caller's effective uid, or
 * root) as a pure decision function. Tested directly with fabricated uids
 * rather than through a chown()'d file: this test process has no privilege
 * to chown a file to a third uid or to root, so a real "owned by someone
 * else" file can't be constructed without running the suite as root. */
static void test_owner_check_helper(void)
{
    TEST_ASSERT_TRUE(oc_seal_owner_ok(1000, 1000));  /* the caller's own file */
    TEST_ASSERT_TRUE(oc_seal_owner_ok(0, 1000));     /* root-owned, any caller */
    TEST_ASSERT_TRUE(oc_seal_owner_ok(0, 0));        /* root running as root */
    TEST_ASSERT_FALSE(oc_seal_owner_ok(1001, 1000)); /* someone else's file */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_seal_opens_with_the_same_row);
    RUN_TEST(test_seal_refuses_anything_else);
    RUN_TEST(test_aad_fields_do_not_run_together);
    RUN_TEST(test_failed_unseal_leaves_pt_untouched);
    RUN_TEST(test_seal_refuses_n_over_max);
    RUN_TEST(test_seal_aad_pk_n_cannot_wrap);
    RUN_TEST(test_key_file_rules);
    RUN_TEST(test_key_file_refuses_fifo);
    RUN_TEST(test_key_file_refuses_directory);
    RUN_TEST(test_owner_check_helper);
    return UNITY_END();
}
