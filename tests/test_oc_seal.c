#define _GNU_SOURCE
/* oc_seal (network-core spec §5, §9.1 "AES-GCM seal/open, including a wrong
 * AAD") and the master key file. */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oc_seal.h"

void setUp(void) {}
void tearDown(void) {}

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
    char path[] = "/tmp/oc_seal_key_XXXXXX", err[160];
    uint8_t k[32];
    int fd = mkstemp(path);
    TEST_ASSERT_TRUE(fd >= 0);
    close(fd);
    write_key(path, 32, 0400);
    TEST_ASSERT_EQUAL_INT(0, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_EQUAL_MEMORY(KEY, k, 32);
    write_key(path, 32, 0640);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "readable by group or others (mode 640)"));
    write_key(path, 31, 0600);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "exactly 32 bytes"));
    unlink(path);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "No such file"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_seal_opens_with_the_same_row);
    RUN_TEST(test_seal_refuses_anything_else);
    RUN_TEST(test_aad_fields_do_not_run_together);
    RUN_TEST(test_key_file_rules);
    return UNITY_END();
}
