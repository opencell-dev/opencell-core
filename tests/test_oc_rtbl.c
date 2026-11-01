/* The signed routing table (OCSS spec 2026-11-01 §3): the codecs, Ed25519,
 * loading a root table, §3.5's acceptance rules one by one, and the §5.5
 * test vector byte for byte. */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "oc_rtbl.h"

void setUp(void) {}
void tearDown(void) {}

/* RFC 8032 §7.1 TEST 1: the delegate in the test vector */
static const char *DSEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
static const char *DPUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static uint8_t ROOT_SEED[32], ROOT_PUB[32], D_SEED[32], D_PUB[32], OTHER_SEED[32], OTHER_PUB[32];
static oc_rtbl_root_t R;
static oc_rtbl_t CUR, NEXT;
static uint8_t FILEBUF[OC_RTBL_ROOT_MAX];
#define NOW 1793500000u

static void keys(void)
{
    uint8_t sig[64];
    memset(ROOT_SEED, 0x01, 32);
    memset(OTHER_SEED, 0x02, 32);
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_unhex(DSEED, D_SEED, 32));
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_sign_seed(ROOT_SEED, (const uint8_t *)"", 0, sig, ROOT_PUB));
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_sign_seed(D_SEED, (const uint8_t *)"", 0, sig, D_PUB));
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_sign_seed(OTHER_SEED, (const uint8_t *)"", 0, sig, OTHER_PUB));
    char h[65];
    oc_rtbl_hex(D_PUB, 32, h);
    TEST_ASSERT_EQUAL_STRING(DPUB, h);
}

static void block(const char *prefix, uint16_t idx, uint16_t home, const char *state)
{
    oc_rtbl_block_t *b = &R.blocks[R.nblocks++];
    memset(b, 0, sizeof(*b));
    snprintf(b->prefix, sizeof(b->prefix), "%s", prefix);
    b->idx = idx;
    b->tenant = 1;
    b->home = home;
    b->nsec = 1;
    b->sec[0] = (uint16_t)(3u - home);
    b->epoch = 1;
    snprintf(b->state, sizeof(b->state), "%s", state);
}

/* The deployed shape: 606 = 1, 503 = 2, 865 = 3, max_idx 3, the delegate. */
static void root_table(uint32_t version)
{
    memset(&R, 0, sizeof(R));
    R.version = version;
    R.issued = NOW;
    R.max_idx = 3;
    R.ncores = 2;
    R.cores[0].id = 1;
    strcpy(R.cores[0].name, "oc-core-1");
    R.cores[1].id = 2;
    strcpy(R.cores[1].name, "oc-core-2");
    block("8831606", 1, 1, "US-KY");
    block("8831503", 2, 2, "US-OR");
    block("8831865", 3, 1, "US-TN");
    oc_rtbl_deleg_t *d = &R.deleg[R.ndeleg++];
    memcpy(d->pub, D_PUB, 32);
    d->scope = OC_RTBL_SCOPE_ADD_NPA;
    d->not_before = NOW - 10u;
    d->not_after = NOW + 365u * 86400u;
    d->tenant = 1;
    d->east = 1;
    d->west = 2;
    for (const char *const *s = OC_RTBL_EAST; *s != NULL; s++) strcpy(d->east_st[d->neast++], *s);
    for (const char *const *s = OC_RTBL_WEST; *s != NULL; s++) strcpy(d->west_st[d->nwest++], *s);
}

/* R encoded and signed with seed: the file's length */
static size_t sign_root(const uint8_t seed[32])
{
    size_t n = oc_rtbl_root_encode(&R, FILEBUF, sizeof(FILEBUF) - 64u);
    TEST_ASSERT_NOT_EQUAL(0, n);
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_sign_seed(seed, FILEBUF, n, FILEBUF + n, NULL));
    return n + 64u;
}

static void loaded(void)
{
    char err[160];
    keys();
    root_table(7);
    size_t n = sign_root(ROOT_SEED);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_rtbl_load(&CUR, 1, ROOT_PUB, FILEBUF, n, err, sizeof(err)), err);
}

/* An addition of npa/idx/state, signed by seed (its pub named in it). */
static size_t addition(uint8_t *blob, uint8_t sig[64], uint16_t seq, const char *npa, uint16_t idx, const char *state,
                       const uint8_t seed[32], const uint8_t pub[32])
{
    oc_rtbl_add_t a;
    memset(&a, 0, sizeof(a));
    a.root_version = 7;
    a.seq = seq;
    a.issued = NOW;
    memcpy(a.delegate, pub, 32);
    a.n = 1;
    strcpy(a.b[0].npa, npa);
    a.b[0].idx = idx;
    strcpy(a.b[0].state, state);
    size_t n = oc_rtbl_add_encode(&a, blob, OC_RTBL_BLOB_MAX);
    TEST_ASSERT_NOT_EQUAL(0, n);
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_sign_seed(seed, blob, n, sig, NULL));
    return n;
}

static int offer(const uint8_t *blob, size_t n, const uint8_t sig[64], uint32_t now, int *fresh, char *msg)
{
    return oc_rtbl_offer(&CUR, &NEXT, 7, blob, n, sig, now, fresh, msg, 96);
}

static void test_a_root_table_loads_and_routes(void)
{
    loaded();
    TEST_ASSERT_EQUAL_UINT(3, CUR.route.n);
    TEST_ASSERT_EQUAL_UINT16(3, CUR.max_idx);
    TEST_ASSERT_EQUAL_UINT16(0, CUR.seq);
    const oc_core_block_t *b = oc_core_route_block(&CUR.route, 2);
    TEST_ASSERT_EQUAL_STRING("8831503", b->prefix);
    TEST_ASSERT_EQUAL_UINT16(2, b->home_core);
    TEST_ASSERT_EQUAL_UINT16(1, b->secondary);
    TEST_ASSERT_EQUAL_STRING("US-OR", b->state);
    TEST_ASSERT_TRUE(oc_core_route_secondary(&CUR.route, b));
    TEST_ASSERT_EQUAL_UINT32(7, oc_rtbl_file_version(FILEBUF, sign_root(ROOT_SEED)));
    TEST_ASSERT_EQUAL_UINT32(NOW + 365u * 86400u, oc_rtbl_deleg_until(&CUR, NOW));
    TEST_ASSERT_EQUAL_UINT32(0, oc_rtbl_deleg_until(&CUR, NOW + 366u * 86400u));
}

static void test_a_bad_root_table_is_refused(void)
{
    char err[160];
    keys();
    root_table(7);
    size_t n = sign_root(OTHER_SEED); /* not the root key */
    TEST_ASSERT_EQUAL_INT(-1, oc_rtbl_load(&CUR, 1, ROOT_PUB, FILEBUF, n, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "signature"));
    n = sign_root(ROOT_SEED);
    TEST_ASSERT_EQUAL_INT(-1, oc_rtbl_load(&CUR, 3, ROOT_PUB, FILEBUF, n, err, sizeof(err))); /* core 3 not listed */
    FILEBUF[20] ^= 1; /* signed bytes changed */
    TEST_ASSERT_EQUAL_INT(-1, oc_rtbl_load(&CUR, 1, ROOT_PUB, FILEBUF, n, err, sizeof(err)));

    static const struct { const char *what; int field; } cases[] = {
        { "duplicate prefix", 1 }, { "duplicate index", 2 }, { "index above max_idx", 3 }, { "home not in directory", 4 },
        { "secondary = home", 5 }, { "bad state", 6 },       { "bad prefix", 7 },          { "delegation east = west", 8 },
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        root_table(7);
        switch (cases[i].field) {
        case 1: strcpy(R.blocks[2].prefix, "8831606"); break;
        case 2: R.blocks[2].idx = 1; break;
        case 3: R.blocks[2].idx = 4; break;
        case 4: R.blocks[2].home = 9; break;
        case 5: R.blocks[2].sec[0] = 1; break;
        case 6: strcpy(R.blocks[2].state, "us-tn"); break;
        case 7: strcpy(R.blocks[2].prefix, "8831911"); break;
        case 8: R.deleg[0].west = 1; break;
        }
        n = sign_root(ROOT_SEED);
        TEST_ASSERT_EQUAL_INT_MESSAGE(-1, oc_rtbl_load(&CUR, 1, ROOT_PUB, FILEBUF, n, err, sizeof(err)), cases[i].what);
    }
    /* a trailing byte inside the signed part */
    root_table(7);
    size_t bn = oc_rtbl_root_encode(&R, FILEBUF, sizeof(FILEBUF));
    FILEBUF[bn] = 0;
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_sign_seed(ROOT_SEED, FILEBUF, bn + 1u, FILEBUF + bn + 1u, NULL));
    TEST_ASSERT_EQUAL_INT(-1, oc_rtbl_load(&CUR, 1, ROOT_PUB, FILEBUF, bn + 65u, err, sizeof(err)));
}

static void test_an_addition_is_taken_once(void)
{
    uint8_t blob[OC_RTBL_BLOB_MAX], sig[64];
    char msg[96];
    int fresh;
    loaded();
    size_t n = addition(blob, sig, 1, "472", 4, "US-NC", D_SEED, D_PUB);
    TEST_ASSERT_EQUAL_INT_MESSAGE(OC_RTBL_OK, offer(blob, n, sig, NOW, &fresh, msg), msg);
    TEST_ASSERT_EQUAL_INT(1, fresh);
    TEST_ASSERT_EQUAL_UINT(4, NEXT.route.n);
    TEST_ASSERT_EQUAL_UINT16(1, NEXT.seq);
    TEST_ASSERT_EQUAL_UINT16(4, NEXT.max_idx);
    const oc_core_block_t *b = oc_core_route_block(&NEXT.route, 4);
    TEST_ASSERT_EQUAL_STRING("8831472", b->prefix);
    TEST_ASSERT_EQUAL_UINT16(1, b->home_core); /* East */
    TEST_ASSERT_EQUAL_UINT16(2, b->secondary);
    TEST_ASSERT_EQUAL_UINT16(1, b->tenant);
    CUR = NEXT;
    TEST_ASSERT_EQUAL_INT(OC_RTBL_OK, offer(blob, n, sig, NOW, &fresh, msg)); /* again: ok, nothing new */
    TEST_ASSERT_EQUAL_INT(0, fresh);
    TEST_ASSERT_EQUAL_UINT(4, NEXT.route.n);
    n = addition(blob, sig, 1, "945", 5, "US-TX", D_SEED, D_PUB); /* another one at seq 1 */
    TEST_ASSERT_EQUAL_INT(OC_RTBL_TAKEN, offer(blob, n, sig, NOW, &fresh, msg));
    n = addition(blob, sig, 2, "945", 5, "US-TX", D_SEED, D_PUB);
    TEST_ASSERT_EQUAL_INT_MESSAGE(OC_RTBL_OK, offer(blob, n, sig, NOW, &fresh, msg), msg);
    TEST_ASSERT_EQUAL_UINT16(2, oc_core_route_block(&NEXT.route, 5)->home_core); /* West */
    TEST_ASSERT_EQUAL_UINT16(1, oc_core_route_block(&NEXT.route, 5)->secondary);
}

static void test_the_rules_refuse(void)
{
    uint8_t blob[OC_RTBL_BLOB_MAX], sig[64];
    char msg[96];
    int fresh;
    loaded();
    size_t n = addition(blob, sig, 1, "472", 4, "US-NC", D_SEED, D_PUB);
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, oc_rtbl_offer(&CUR, &NEXT, 8, blob, n, sig, NOW, &fresh, msg, 96)); /* rule 3 */
    TEST_ASSERT_NOT_NULL(strstr(msg, "root version"));
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n - 1u, sig, NOW, &fresh, msg)); /* rule 2 */
    TEST_ASSERT_NOT_NULL(strstr(msg, "malformed"));
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW + 400u * 86400u, &fresh, msg)); /* rule 4: expired */
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW - 20u, &fresh, msg));           /* not yet */
    sig[0] ^= 1;
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW, &fresh, msg)); /* rule 5 */
    TEST_ASSERT_NOT_NULL(strstr(msg, "signature"));
    n = addition(blob, sig, 1, "472", 4, "US-NC", OTHER_SEED, OTHER_PUB); /* not a delegate */
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW, &fresh, msg));
    TEST_ASSERT_NOT_NULL(strstr(msg, "delegation"));
    n = addition(blob, sig, 2, "472", 4, "US-NC", D_SEED, D_PUB); /* rule 6: a gap */
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW, &fresh, msg));
    TEST_ASSERT_NOT_NULL(strstr(msg, "out of order"));
    n = addition(blob, sig, 1, "606", 4, "US-KY", D_SEED, D_PUB); /* rule 7: a block already */
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW, &fresh, msg));
    n = addition(blob, sig, 1, "472", 3, "US-NC", D_SEED, D_PUB); /* index not above max_idx */
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW, &fresh, msg));
    n = addition(blob, sig, 1, "472", 4, "FR", D_SEED, D_PUB); /* a state in neither list */
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW, &fresh, msg));
    TEST_ASSERT_NOT_NULL(strstr(msg, "neither"));
    TEST_ASSERT_EQUAL_UINT(3, CUR.route.n); /* nothing changed */

    /* rule 4: a root table that revokes the delegate */
    char err[160];
    root_table(7);
    memcpy(R.revoked[R.nrevoked++], D_PUB, 32);
    size_t fn = sign_root(ROOT_SEED);
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_load(&CUR, 1, ROOT_PUB, FILEBUF, fn, err, sizeof(err)));
    n = addition(blob, sig, 1, "472", 4, "US-NC", D_SEED, D_PUB);
    TEST_ASSERT_EQUAL_INT(OC_RTBL_INVALID, offer(blob, n, sig, NOW, &fresh, msg));
    TEST_ASSERT_EQUAL_UINT32(0, oc_rtbl_deleg_until(&CUR, NOW));
}

static void test_state_codes(void)
{
    TEST_ASSERT_TRUE(oc_rtbl_state_ok("US-KY"));
    TEST_ASSERT_TRUE(oc_rtbl_state_ok("CA-ON"));
    TEST_ASSERT_TRUE(oc_rtbl_state_ok("KY"));
    TEST_ASSERT_FALSE(oc_rtbl_state_ok("MX-DF"));
    TEST_ASSERT_FALSE(oc_rtbl_state_ok("US-K"));
    TEST_ASSERT_FALSE(oc_rtbl_state_ok("us-ky"));
    TEST_ASSERT_FALSE(oc_rtbl_state_ok(""));
    unsigned e = 0, w = 0;
    for (const char *const *s = OC_RTBL_EAST; *s != NULL; s++, e++) TEST_ASSERT_TRUE(oc_rtbl_state_ok(*s));
    for (const char *const *s = OC_RTBL_WEST; *s != NULL; s++, w++) TEST_ASSERT_TRUE(oc_rtbl_state_ok(*s));
    TEST_ASSERT_EQUAL_UINT(53, e); /* 26 states + DC + PR, VI; 6 provinces; 18 countries */
    TEST_ASSERT_EQUAL_UINT(34, w); /* 24 states + GU, MP, AS; 7 provinces and territories */
}

/* OCSS spec §5.5: the vector the portal's TypeScript reproduces. */
static void test_the_vector(void)
{
    static const char *BLOB =
        "4f4352410107000000010060a3e66ad75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a01343732c7010555532d"
        "4e43";
    oc_rtbl_add_t a;
    uint8_t blob[OC_RTBL_BLOB_MAX], sig[64], pub[32];
    char h[2 * OC_RTBL_BLOB_MAX + 1];
    keys();
    memset(&a, 0, sizeof(a));
    a.root_version = 7;
    a.seq = 1;
    a.issued = NOW;
    memcpy(a.delegate, D_PUB, 32);
    a.n = 1;
    strcpy(a.b[0].npa, "472");
    a.b[0].idx = 455;
    strcpy(a.b[0].state, "US-NC");
    size_t n = oc_rtbl_add_encode(&a, blob, sizeof(blob));
    oc_rtbl_hex(blob, n, h);
    printf("vector blob (%zu bytes): %s\n", n, h);
    TEST_ASSERT_EQUAL_STRING(BLOB, h);
    TEST_ASSERT_EQUAL_INT(0, oc_rtbl_sign_seed(D_SEED, blob, n, sig, pub));
    oc_rtbl_hex(sig, 64, h);
    printf("vector sig: %s\n", h);
    /* the same from Python's cryptography 43 and openssl pkeyutl -rawin (2026-11-01) */
    TEST_ASSERT_EQUAL_STRING("0fb6cb54a4472f1fe3a1aa09e1ecc95cd976811a2dcc390fc9b0a5f81b0b2469e78aa3025efdf17ca806397f9e1"
                             "deb41cae644ae09bc5f06c2d5e0bdd630fb0b", h);
    TEST_ASSERT_TRUE(oc_rtbl_verify(D_PUB, blob, n, sig));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a_root_table_loads_and_routes);
    RUN_TEST(test_a_bad_root_table_is_refused);
    RUN_TEST(test_an_addition_is_taken_once);
    RUN_TEST(test_the_rules_refuse);
    RUN_TEST(test_state_codes);
    RUN_TEST(test_the_vector);
    return UNITY_END();
}
