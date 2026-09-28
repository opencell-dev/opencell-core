/* The in-memory store against the store contract, and what only the
 * in-memory store has: a failing commit undoes the transaction, and the
 * record logs keep the newest entries. */
#include "unity.h"

#include <string.h>

#include "core_store_contract.h"
#include "lc_core_mem.h"

void setUp(void) {}
void tearDown(void) {}

static lc_core_mem_t mem;

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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mem_store_keeps_the_contract);
    RUN_TEST(test_failed_commit_undoes_everything_since_begin);
    RUN_TEST(test_logs_keep_the_newest);
    return UNITY_END();
}
