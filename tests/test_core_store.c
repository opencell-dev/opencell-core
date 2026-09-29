/* The in-memory store against the store contract, and what only the
 * in-memory store has: a failing commit undoes the transaction, the record
 * logs keep the newest entries, each table refuses past its bound without
 * disturbing what is already there, and begin()/commit() refuse misuse. */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "core_store_contract.h"
#include "lc_core_mem.h"

void setUp(void) {}
void tearDown(void) {}

static lc_core_mem_t mem;

/* A distinct valid number for index i: "883" + a non-'1' 4th digit keeps
 * digits_ok() out of the NANP branch, so any digit string is accepted. */
static void num_for(unsigned i, uint8_t out[LC_SIG_NUMBER_LEN])
{
    char text[16];
    snprintf(text, sizeof text, "8832%07u", i);
    contract_num(text, out);
}

static void test_mem_store_keeps_the_contract(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    store_contract(&st);
}

static void test_failed_commit_undoes_everything_since_begin(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_sub_t s, got;
    memset(&s, 0, sizeof(s));
    contract_num("+883160655501234", s.number);
    s.sqn = 10;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    mem.fail_commits = 1;
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    s.sqn = 11;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_UINT64(10, got.sqn); /* as before the transaction */
    TEST_ASSERT_EQUAL_UINT(0, mem.commits);
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(0, st.commit(st.ctx)); /* only the one commit failed */
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_UINT64(11, got.sqn);
}

/* A put that fails because its table is full dooms the transaction
 * (txn_failed): commit must undo and return -1. That flag must then reset,
 * not linger and doom the next, unrelated transaction too. */
static void test_failed_put_dooms_then_the_flag_resets(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_netkey_t k, got;
    memset(&k, 0, sizeof(k));
    for (unsigned i = 0; i < LC_CORE_MEM_KEYS; i++) {
        k.key_id = (uint16_t)(i + 1);
        TEST_ASSERT_EQUAL_INT(0, st.netkey_put(st.ctx, &k)); /* fills the table */
    }
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    k.key_id = (uint16_t)(LC_CORE_MEM_KEYS + 1);
    TEST_ASSERT_EQUAL_INT(-1, st.netkey_put(st.ctx, &k)); /* one past the bound: fails */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx)); /* the failed put dooms the whole transaction */
    TEST_ASSERT_EQUAL_INT(-1, st.netkey_get(st.ctx, k.key_id, &got));
    TEST_ASSERT_EQUAL_UINT(0, mem.commits);

    lc_core_sub_t s, sgot;
    memset(&s, 0, sizeof(s));
    contract_num("+883200000000002", s.number);
    s.sqn = 42;
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s)); /* fits: does not fail */
    TEST_ASSERT_EQUAL_INT(0, st.commit(st.ctx)); /* the flag did not linger doomed */
    TEST_ASSERT_EQUAL_UINT(1, mem.commits);
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &sgot));
    TEST_ASSERT_EQUAL_UINT64(42, sgot.sqn);
}

static void test_logs_keep_the_newest(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_audit_t a;
    memset(&a, 0, sizeof(a));
    for (unsigned i = 0; i < LC_CORE_MEM_LOG + 5u; i++) {
        a.event = i == 3 ? LC_CORE_AUDIT_RESYNC : LC_CORE_AUDIT_REGISTER;
        a.ts = i;
        st.audit_add(st.ctx, &a);
    }
    TEST_ASSERT_NULL(lc_core_mem_audit(&mem, LC_CORE_AUDIT_RESYNC)); /* overwritten */
    const lc_core_audit_t *last = lc_core_mem_audit(&mem, LC_CORE_AUDIT_REGISTER);
    TEST_ASSERT_NOT_NULL(last);
    TEST_ASSERT_EQUAL_UINT32(LC_CORE_MEM_LOG + 4u, last->ts);
    TEST_ASSERT_NULL(lc_core_mem_audit(&mem, LC_CORE_AUDIT_ACTIVATE));
}

static void test_netkey_table_fills_then_refuses(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_netkey_t k, got;
    memset(&k, 0, sizeof(k));
    for (unsigned i = 0; i < LC_CORE_MEM_KEYS; i++) {
        k.key_id = (uint16_t)(i + 1);
        k.created = i;
        TEST_ASSERT_EQUAL_INT(0, st.netkey_put(st.ctx, &k)); /* the last of these fills the table */
    }
    k.key_id = (uint16_t)(LC_CORE_MEM_KEYS + 1);
    k.created = 999;
    TEST_ASSERT_EQUAL_INT(-1, st.netkey_put(st.ctx, &k)); /* one past the bound */
    TEST_ASSERT_EQUAL_INT(-1, st.netkey_get(st.ctx, k.key_id, &got)); /* not added */
    TEST_ASSERT_EQUAL_INT(0, st.netkey_get(st.ctx, 1, &got)); /* first entry untouched */
    TEST_ASSERT_EQUAL_UINT32(0, got.created);
}

static void test_cell_table_fills_then_refuses(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_cell_t c, got;
    memset(&c, 0, sizeof(c));
    for (unsigned i = 0; i < LC_CORE_MEM_CELLS; i++) {
        c.cell_id = i + 1;
        c.last_seen = i;
        TEST_ASSERT_EQUAL_INT(0, st.cell_put(st.ctx, &c));
    }
    c.cell_id = LC_CORE_MEM_CELLS + 1;
    c.last_seen = 999;
    TEST_ASSERT_EQUAL_INT(-1, st.cell_put(st.ctx, &c));
    TEST_ASSERT_EQUAL_INT(-1, st.cell_get(st.ctx, c.cell_id, &got));
    TEST_ASSERT_EQUAL_INT(0, st.cell_get(st.ctx, 1, &got));
    TEST_ASSERT_EQUAL_UINT32(0, got.last_seen);
}

static void test_sub_table_fills_then_refuses(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_sub_t s, got;
    uint8_t first[LC_SIG_NUMBER_LEN];
    memset(&s, 0, sizeof(s));
    for (unsigned i = 0; i < LC_CORE_MEM_SUBS; i++) {
        num_for(i, s.number);
        if (i == 0) memcpy(first, s.number, LC_SIG_NUMBER_LEN);
        s.sqn = i;
        TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    }
    num_for(LC_CORE_MEM_SUBS, s.number);
    s.sqn = 999;
    TEST_ASSERT_EQUAL_INT(-1, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(-1, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, first, &got));
    TEST_ASSERT_EQUAL_UINT64(0, got.sqn);
}

static void test_token_table_fills_then_refuses(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_token_t t, got;
    uint8_t first_id[8];
    memset(&t, 0, sizeof(t));
    contract_num("+883200000000001", t.number);
    for (unsigned i = 0; i < LC_CORE_MEM_TOKENS; i++) {
        memset(t.token_id, 0, sizeof t.token_id);
        t.token_id[6] = (uint8_t)(i >> 8);
        t.token_id[7] = (uint8_t)i;
        if (i == 0) memcpy(first_id, t.token_id, sizeof first_id);
        t.used_at = i;
        TEST_ASSERT_EQUAL_INT(0, st.token_put(st.ctx, &t));
    }
    memset(t.token_id, 0, sizeof t.token_id);
    t.token_id[6] = (uint8_t)(LC_CORE_MEM_TOKENS >> 8);
    t.token_id[7] = (uint8_t)LC_CORE_MEM_TOKENS;
    t.used_at = 999;
    TEST_ASSERT_EQUAL_INT(-1, st.token_put(st.ctx, &t));
    TEST_ASSERT_EQUAL_INT(-1, st.token_get(st.ctx, t.token_id, &got));
    TEST_ASSERT_EQUAL_INT(0, st.token_get(st.ctx, first_id, &got));
    TEST_ASSERT_EQUAL_UINT32(0, got.used_at);
}

static void test_av_table_fills_then_refuses(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_av_issued_t a, got;
    uint8_t first_rand[16];
    memset(&a, 0, sizeof(a));
    contract_num("+883200000000001", a.number);
    for (unsigned i = 0; i < LC_CORE_MEM_AVS; i++) {
        memset(a.rand, 0, sizeof a.rand);
        a.rand[14] = (uint8_t)(i >> 8);
        a.rand[15] = (uint8_t)i;
        if (i == 0) memcpy(first_rand, a.rand, sizeof first_rand);
        a.issued = i;
        TEST_ASSERT_EQUAL_INT(0, st.av_put(st.ctx, &a));
    }
    memset(a.rand, 0, sizeof a.rand);
    a.rand[14] = (uint8_t)(LC_CORE_MEM_AVS >> 8);
    a.rand[15] = (uint8_t)LC_CORE_MEM_AVS;
    a.issued = 999;
    TEST_ASSERT_EQUAL_INT(-1, st.av_put(st.ctx, &a));
    TEST_ASSERT_EQUAL_INT(-1, st.av_get(st.ctx, a.number, a.rand, &got));
    TEST_ASSERT_EQUAL_INT(0, st.av_get(st.ctx, a.number, first_rand, &got));
    TEST_ASSERT_EQUAL_UINT32(0, got.issued);
}

static void test_loc_table_fills_then_refuses(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_loc_t l, got;
    uint8_t first[LC_SIG_NUMBER_LEN];
    memset(&l, 0, sizeof(l));
    for (unsigned i = 0; i < LC_CORE_MEM_SUBS; i++) {
        num_for(i, l.number);
        if (i == 0) memcpy(first, l.number, LC_SIG_NUMBER_LEN);
        l.cell_id = i;
        l.expires = i;
        TEST_ASSERT_EQUAL_INT(0, st.loc_put(st.ctx, &l));
    }
    num_for(LC_CORE_MEM_SUBS, l.number);
    l.expires = 999;
    TEST_ASSERT_EQUAL_INT(-1, st.loc_put(st.ctx, &l));
    TEST_ASSERT_EQUAL_INT(-1, st.loc_get(st.ctx, l.number, &got));
    TEST_ASSERT_EQUAL_INT(0, st.loc_get(st.ctx, first, &got));
    TEST_ASSERT_EQUAL_UINT32(0, got.expires);
}

static void test_begin_twice_is_refused(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_sub_t s, got;
    memset(&s, 0, sizeof(s));
    contract_num("+883200000000001", s.number);
    s.sqn = 1;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s)); /* before any transaction */
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    s.sqn = 2;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(-1, st.begin(st.ctx)); /* already inside a transaction: refused */
    s.sqn = 3;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s)); /* still the one open transaction */
    mem.fail_commits = 1;
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    /* the failed nested begin() must not have moved the undo point: undo
     * restores all the way back to before the *first* begin (sqn 1), not to
     * sqn 2 as it would if the second begin() had re-snapshotted. */
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_UINT64(1, got.sqn);
    TEST_ASSERT_EQUAL_UINT(0, mem.commits);
}

static void test_commit_without_begin_is_refused(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_sub_t s, got;
    memset(&s, 0, sizeof(s));
    contract_num("+883200000000001", s.number);
    s.sqn = 1;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx)); /* no matching begin() */
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_UINT64(1, got.sqn); /* unchanged */
    TEST_ASSERT_EQUAL_UINT(0, mem.commits); /* not counted as a commit */
    /* a real transaction still works afterward: the guard left in_txn sane */
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    s.sqn = 2;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(0, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_UINT64(2, got.sqn);
    TEST_ASSERT_EQUAL_UINT(1, mem.commits);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mem_store_keeps_the_contract);
    RUN_TEST(test_failed_commit_undoes_everything_since_begin);
    RUN_TEST(test_failed_put_dooms_then_the_flag_resets);
    RUN_TEST(test_logs_keep_the_newest);
    RUN_TEST(test_netkey_table_fills_then_refuses);
    RUN_TEST(test_cell_table_fills_then_refuses);
    RUN_TEST(test_sub_table_fills_then_refuses);
    RUN_TEST(test_token_table_fills_then_refuses);
    RUN_TEST(test_av_table_fills_then_refuses);
    RUN_TEST(test_loc_table_fills_then_refuses);
    RUN_TEST(test_begin_twice_is_refused);
    RUN_TEST(test_commit_without_begin_is_refused);
    return UNITY_END();
}
