/* The block table (network-core spec §14.2-14.3) and the number policy
 * (§7.11): the longest prefix wins, "am I home?", block indexes in token
 * ids, reserved numbers, auto-assigned candidates. */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "oc_core_route.h"

void setUp(void) {}
void tearDown(void) {}

static const oc_core_block_t *find(const oc_core_route_t *r, const char *number)
{
    uint8_t n[OC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_sig_number_to_bcd(number, strlen(number), n), number);
    return oc_core_route_find(r, n);
}

/* The §14.2 example, seen from core 1. */
static void example(oc_core_route_t *r)
{
    oc_core_route_init(r, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(r, "8831606", 1, 1));
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(r, "8831606555", 2, 2));
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(r, "8831859", 3, 1));
}

static void test_longest_prefix_wins_and_home_is_known(void)
{
    oc_core_route_t r;
    example(&r);
    const oc_core_block_t *b = find(&r, "+883160655501234");
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_UINT16(2, b->block_idx); /* the exchange block inside the area code */
    TEST_ASSERT_FALSE(oc_core_route_home(&r, b));
    b = find(&r, "+883160677701234");
    TEST_ASSERT_EQUAL_UINT16(1, b->block_idx);
    TEST_ASSERT_TRUE(oc_core_route_home(&r, b));
    TEST_ASSERT_EQUAL_UINT16(3, find(&r, "+883185955520000")->block_idx);
    TEST_ASSERT_NULL(find(&r, "+883121255501234")); /* no block: no route */
    TEST_ASSERT_NULL(find(&r, "+883442079460000"));
    TEST_ASSERT_FALSE(oc_core_route_home(&r, NULL));
    TEST_ASSERT_EQUAL_PTR(&r.b[2], oc_core_route_block(&r, 3));
    TEST_ASSERT_NULL(oc_core_route_block(&r, 4));
    static const uint8_t zeros[OC_SIG_NUMBER_LEN] = { 0 };
    TEST_ASSERT_NULL(oc_core_route_find(&r, zeros)); /* not a number */
}

static void test_bad_blocks_are_refused(void)
{
    oc_core_route_t r;
    example(&r);
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831606", 9, 1));     /* the prefix again */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831212", 2, 1));     /* the index again */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831212", 0, 1));     /* index 0 */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "88316065", 9, 1));    /* NANP: NPA or NPA-NXX only */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8841606", 9, 1));     /* not 883 */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "883-1-212", 9, 1));   /* digits only */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "883", 9, 1));         /* too short */
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&r, "88344", 9, 1));        /* a whole country code */
    TEST_ASSERT_EQUAL_UINT16(9, find(&r, "+883442079460000")->block_idx);
    oc_core_route_init(&r, 1);
    for (unsigned i = 0; i < OC_CORE_BLOCKS; i++) {
        char p[16];
        unsigned npa = 200u + i + (i >= 11u ? 1u : 0u); /* skip 211: N11, illegal */
        snprintf(p, sizeof(p), "8831%03u", npa);
        TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&r, p, (uint16_t)(i + 1u), 1));
    }
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831999", 999, 1)); /* full */
}

static void test_illegal_nanp_codes_are_refused(void)
{
    oc_core_route_t r;
    oc_core_route_init(&r, 1);
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831011", 1, 1));    /* NPA first digit not 2-9 */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831883", 1, 1));    /* NPA is 883 */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831911", 1, 1));    /* NPA is N11 */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "88316061115", 1, 1)); /* not NPA-NXX length */
    TEST_ASSERT_EQUAL_INT(-1, oc_core_route_add(&r, "8831606111", 1, 1));  /* NXX is N11 */
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&r, "8831606", 1, 1));      /* legal NPA still accepted */
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&r, "8831606555", 2, 1));   /* legal NPA-NXX still accepted */
    /* A full-length (15-digit), non-NANP prefix stays a whole block on its own. */
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&r, "883442079460000", 3, 1));
}

static void test_token_ids_carry_the_block(void)
{
    static const uint8_t r6[6] = { 1, 2, 3, 4, 5, 6 };
    static const uint8_t want[8] = { 0x01, 0x02, 1, 2, 3, 4, 5, 6 };
    uint8_t id[8];
    oc_core_token_id(0x0102, r6, id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, id, 8);
    TEST_ASSERT_EQUAL_UINT16(0x0102, oc_core_token_block(id));
}

static int reserved(const char *number)
{
    uint8_t n[OC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_sig_number_to_bcd(number, strlen(number), n), number);
    return oc_core_number_reserved(n);
}

static void test_reserved_numbers(void)
{
    TEST_ASSERT_TRUE(reserved("+883160655500000"));
    TEST_ASSERT_TRUE(reserved("+883160655500001"));
    TEST_ASSERT_TRUE(reserved("+883160655500100")); /* the echo service is configured, not assigned */
    TEST_ASSERT_TRUE(reserved("+883160655500911"));
    TEST_ASSERT_TRUE(reserved("+883160655500999"));
    TEST_ASSERT_TRUE(reserved("+883160655509911"));
    TEST_ASSERT_TRUE(reserved("+883160655599999"));
    TEST_ASSERT_FALSE(reserved("+883160655501000"));
    TEST_ASSERT_FALSE(reserved("+883160655501234"));
    TEST_ASSERT_FALSE(reserved("+883160655599998"));
    TEST_ASSERT_FALSE(reserved("+883442079400000")); /* no plan for other country codes yet */
}

static void test_picked_numbers_are_valid_candidates(void)
{
    oc_core_route_t r;
    example(&r);
    uint8_t rnd[8], n[OC_SIG_NUMBER_LEN];
    char text[OC_SIG_NUMBER_TEXT];
    uint32_t x = 1;
    for (unsigned i = 0; i < 5000; i++) {
        for (int k = 0; k < 8; k++) rnd[k] = (uint8_t)((x = x * 1103515245u + 12345u) >> 16);
        TEST_ASSERT_EQUAL_INT(0, oc_core_number_pick(&r.b[0], rnd, n)); /* NPA block: the NXX is picked too */
        TEST_ASSERT_TRUE(oc_sig_number_valid(n));
        TEST_ASSERT_FALSE(oc_core_number_reserved(n));
        oc_sig_number_to_text(n, text);
        TEST_ASSERT_EQUAL_INT(0, strncmp(text, "+8831606", 8));
        TEST_ASSERT_EQUAL_INT(0, oc_core_number_pick(&r.b[1], rnd, n)); /* NPA-NXX block */
        TEST_ASSERT_FALSE(oc_core_number_reserved(n));
        oc_sig_number_to_text(n, text);
        TEST_ASSERT_EQUAL_INT(0, strncmp(text, "+8831606555", 11));
    }
    oc_core_block_t uk = { "88344", 9, 1 };
    TEST_ASSERT_EQUAL_INT(-1, oc_core_number_pick(&uk, rnd, n)); /* not a NANP block */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_longest_prefix_wins_and_home_is_known);
    RUN_TEST(test_bad_blocks_are_refused);
    RUN_TEST(test_illegal_nanp_codes_are_refused);
    RUN_TEST(test_token_ids_carry_the_block);
    RUN_TEST(test_reserved_numbers);
    RUN_TEST(test_picked_numbers_are_valid_candidates);
    return UNITY_END();
}
