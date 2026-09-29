#define _GNU_SOURCE
/* The admin commands (network-core spec §4.2, §17 decision 1) on a core's
 * database with no daemon (the --offline path; the daemon runs the same
 * code over its socket), the channel-list text, and the import of
 * ocbench's HSS. */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oc_sig_crypto.h"
#include "oc_sig_qr.h"
#include "oc_admin.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t KEY[32] = { 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                                 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 };
static uint32_t rng = 3;
static void rnd(uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((rng = rng * 1103515245u + 12345u) >> 16);
}

static oc_sql_t *sql;
static oc_core_route_t route;
static oc_core_cfg_t cfg;
static oc_admin_t adm;
static oc_buf_t out;

static void world(void)
{
    char err[256];
    oc_sql_cfg_t c = { ":memory:", KEY, rnd, NULL, 0 };
    sql = oc_sql_open(&c, err, sizeof(err));
    TEST_ASSERT_NOT_NULL_MESSAGE(sql, err);
    oc_core_route_init(&route, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&route, "8831606", 1, 1));
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    oc_sig_number_to_bcd("+883160655500100", 16, cfg.echo_number);
    memset(&adm, 0, sizeof(adm));
    adm.sql = sql;
    adm.route = &route;
    adm.cfg = &cfg;
    adm.random = rnd;
    adm.uid = 1000;
}

static void done(void)
{
    oc_sql_close(sql);
    oc_buf_free(&out);
}

/* Runs one command line (words split on spaces); the output is in out.p. */
static int run(const char *line)
{
    char buf[512], *argv[16];
    int argc = 0;
    snprintf(buf, sizeof(buf), "%s", line);
    for (char *t = strtok(buf, " "); t != NULL && argc < 16; t = strtok(NULL, " ")) argv[argc++] = t;
    out.n = 0;
    if (out.p != NULL) out.p[0] = '\0';
    return oc_admin_run(&adm, argc, argv, &out);
}

#define HAS(s) TEST_ASSERT_NOT_NULL_MESSAGE(strstr(out.p != NULL ? out.p : "", s), out.p != NULL ? out.p : "(no output)")

static void test_first_setup_and_subscribers(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("status"));
    HAS("network key 1 (missing: net init)");
    HAS("offline");
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-606-555-01234"));
    HAS("no network key 1 in the database");
    TEST_ASSERT_EQUAL_INT(0, run("net init --period 900"));
    HAS("network key 1 made, registration period 900 s");
    TEST_ASSERT_EQUAL_INT(1, run("net init"));
    HAS("exists already");
    TEST_ASSERT_EQUAL_INT(0, run("cell add 1 benchA --mode part15"));
    TEST_ASSERT_EQUAL_INT(1, run("cell add 1 again"));
    TEST_ASSERT_EQUAL_INT(1, run("cell add 2 x --mode part16"));
    HAS("mode 'part16': part15 or part97");
    TEST_ASSERT_EQUAL_INT(0, run("sub add +883-1-606-555-01234"));
    HAS("subscriber +883160655501234 (+883-1-606-555-01234) added");
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-606-555-01234"));
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-606-555-00911")); /* reserved */
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-859-555-01234")); /* not our block */
    TEST_ASSERT_EQUAL_INT(1, run("sub add 555-1234"));
    HAS("not a full OpenCell number");
    TEST_ASSERT_EQUAL_INT(0, run("sub add")); /* a number picked for us */
    HAS("subscriber +8831606");
    TEST_ASSERT_EQUAL_INT(0, run("status"));
    HAS("subscribers 2 (0 activated, 0 disabled)");
    HAS("cell 1 \"benchA\": part15, enabled, list 0, not linked");
    done();
}

/* The code a phone scans, and what disabling does to it. */
static void test_issue_and_disable(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("net init"));
    TEST_ASSERT_EQUAL_INT(0, run("sub add +883160655501235"));
    TEST_ASSERT_EQUAL_INT(0, run("sub issue +883-1-606-555-01235 --valid-h 2"));
    HAS("valid 2 h");
    char *code = strstr(out.p, "opencell:2:");
    TEST_ASSERT_NOT_NULL(code);
    oc_sig_qr_t qr;
    TEST_ASSERT_EQUAL_INT(0, oc_sig_qr_parse(code, strcspn(code, "\n"), &qr));
    char t[OC_SIG_NUMBER_TEXT];
    oc_sig_number_to_text(qr.number, t);
    TEST_ASSERT_EQUAL_STRING("+883160655501235", t);
    TEST_ASSERT_EQUAL_UINT16(1, qr.key_id);
    TEST_ASSERT_EQUAL_UINT16(1, (uint16_t)((qr.token_id[0] << 8) | qr.token_id[1])); /* block index (§14.3) */
    TEST_ASSERT_EQUAL_INT(1, run("sub issue +883160655501235 --valid-h 0"));
    TEST_ASSERT_EQUAL_INT(0, run("sub disable +883160655501235"));
    TEST_ASSERT_EQUAL_INT(1, run("sub issue +883160655501235"));
    TEST_ASSERT_EQUAL_INT(0, run("sub list"));
    HAS("+883160655501235  disabled  not activated");
    TEST_ASSERT_EQUAL_INT(0, run("audit 50"));
    HAS("ADMIN        -  tmid 00000000  cell 0  u1000 sub disable +883160655501235");
    HAS("u1000 (refused) sub issue +883160655501235");
    HAS("TOKEN_ISSUE");
    HAS("SUB_DISABLE");
    TEST_ASSERT_EQUAL_INT(2, run("sub frobnicate"));
    HAS("commands: status");
    done();
}

static void test_channel_lists(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("net init"));
    TEST_ASSERT_EQUAL_INT(0, run("list set 3 917.25,922.25:fixed"));
    HAS("list 3: version 1, 917.25 922.25:fixed");
    TEST_ASSERT_EQUAL_INT(0, run("list set 3 none"));
    HAS("list 3: version 2, (empty)");
    TEST_ASSERT_EQUAL_INT(1, run("list set 3 917.3"));
    HAS("'917.3' is not a 915 grid channel");
    TEST_ASSERT_EQUAL_INT(1, run("list set 0 917.25"));
    TEST_ASSERT_EQUAL_INT(0, run("list show"));
    HAS("list 3: version 2, (empty)");
    oc_sig_chan_list_t l;
    char err[96];
    TEST_ASSERT_EQUAL_INT(-1, oc_chan_parse("917.25:fast", &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_STRING("'917.25:fast': only ':fixed' may follow a frequency", err);
    TEST_ASSERT_EQUAL_INT(-1, oc_chan_parse("917.25, 922.25", &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_INT(-1, oc_chan_parse("902.25,902.75,903.25,903.75,904.25,904.75,905.25,905.75,906.25,906.75,"
                                            "907.25,907.75,908.25",
                                            &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_STRING("more than 12 entries", err);
    done();
}

/* An ocbench HSS file as ocb_hss_save wrote it. */
static char hss[64];
static uint8_t net_sk[32], net_pk[32];

static void write_hss(const char *extra, uint16_t key_id)
{
    char line[512];
    for (int i = 0; i < 32; i++) net_sk[i] = (uint8_t)(0x40 + i);
    TEST_ASSERT_EQUAL_INT(0, oc_sig_x25519_public(net_sk, net_pk));
    strcpy(hss, "/tmp/oc_admin_hss_XXXXXX");
    int fd = mkstemp(hss);
    TEST_ASSERT_TRUE(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fprintf(f, "# OpenCell network stand-in HSS (ocbench). Holds secrets: keep it private.\n");
    int n = snprintf(line, sizeof(line), "network key_id=%u sk=", key_id);
    for (int i = 0; i < 32; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", net_sk[i]);
    n += snprintf(line + n, sizeof(line) - (size_t)n, " pk=");
    for (int i = 0; i < 32; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", net_pk[i]);
    fprintf(f, "%s mode=part15 period=1800\n", line);
    fprintf(f, "sub number=+883160655501234 token_id=d5d37c57bd4ac802 token_secret=00112233445566778899aabbccddeeff "
               "expiry=1790637771 used=1 tmid=76ad0488 activated=1 k=0102030405060708090a0b0c0d0e0f10 "
               "opc=1112131415161718191a1b1c1d1e1f20 sqn=00000000001c\n");
    fprintf(f, "sub number=+883160655501235 token_id=e7cc4b4ba74a0070 token_secret=00112233445566778899aabbccddeeff "
               "expiry=1790637771 used=1 tmid=76ae2064 activated=1 k=2122232425262728292a2b2c2d2e2f30 "
               "opc=3132333435363738393a3b3c3d3e3f40 sqn=000000000005\n");
    fprintf(f, "sub number=+883160655509999 token_id=b8e799853e97664a token_secret=00112233445566778899aabbccddeeff "
               "expiry=1790637771 used=0 tmid=00000000 activated=0 k=00000000000000000000000000000000 "
               "opc=00000000000000000000000000000000 sqn=000000000000\n");
    fputs(extra, f);
    fclose(f);
}

static void test_import_keeps_activated_terminals(void)
{
    world();
    write_hss("", 1);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(0, run(cmd));
    HAS("network key 1 imported");
    HAS("+883160655501234  terminal 76ad0488  sqn 28  imported");
    HAS("+883160655509999  not activated: give it a code with `oc-core admin sub issue +883160655509999`");
    oc_core_store_t st = oc_sql_store(sql);
    oc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, st.sub_by_tmid(st.ctx, 0x76ae2064u, &s));
    TEST_ASSERT_EQUAL_UINT8(0x21, s.k[0]);
    TEST_ASSERT_EQUAL_UINT8(0x40, s.opc[15]);
    TEST_ASSERT_EQUAL_UINT64(5, s.sqn);
    oc_core_netkey_t key;
    TEST_ASSERT_EQUAL_INT(0, st.netkey_get(st.ctx, 1, &key));
    TEST_ASSERT_EQUAL_MEMORY(net_sk, key.sk, 32);
    TEST_ASSERT_EQUAL_UINT16(1800, key.period_s);
    TEST_ASSERT_EQUAL_INT(1, run(cmd)); /* twice: refused whole */
    HAS("+883160655501234: already a subscriber");
    TEST_ASSERT_EQUAL_INT(0, run("sub issue +883160655509999")); /* the network key issues codes */
    unlink(hss);
    done();
}

/* A bad line anywhere, a key id the config doesn't use, a TMID twice, or a
 * daemon that is running: nothing is written. */
static void test_import_is_all_or_nothing(void)
{
    char cmd[128];
    world();
    write_hss("sub number=+883160655501236 tmid=zz\n", 1);
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS(":6: not an ocbench HSS line (nothing imported)");
    unlink(hss);
    write_hss("", 2);
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS("network key 2, but key_id = 1 in oc-core.conf");
    unlink(hss);
    write_hss("sub number=+883160655501236 token_id=0000000000000000 token_secret=00000000000000000000000000000000 "
              "expiry=0 used=1 tmid=76ad0488 activated=1 k=00000000000000000000000000000000 "
              "opc=00000000000000000000000000000000 sqn=000000000000\n",
              1);
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS("twice in the file");
    TEST_ASSERT_EQUAL_INT(0, run("status"));
    HAS("subscribers 0");
    oc_core_t fake; /* any non-NULL core: the daemon is running */
    adm.core = &fake;
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS("import-ocb-hss runs only with --offline");
    adm.core = NULL;
    unlink(hss);
    done();
}

static void exec(const char *s)
{
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(sql), s, NULL, NULL, NULL));
}

#define HASNT(s) TEST_ASSERT_NULL_MESSAGE(strstr(out.p != NULL ? out.p : "", s), out.p)

/* A store that can't answer is a failure, never "none", "exists" or "not
 * found" (oc_core_store.h): the operator is told it failed. */
static void test_a_store_error_is_never_none_or_exists(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("net init"));
    TEST_ASSERT_EQUAL_INT(0, run("sub add +883160655501234"));
    TEST_ASSERT_EQUAL_INT(0, run("cell add 1 benchA"));

    exec("UPDATE subscriber SET k_enc = zeroblob(45)"); /* sealed keys that don't open */
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883160655501234"));
    HAS("store error");
    HASNT("already");
    TEST_ASSERT_EQUAL_INT(1, run("sub issue +883160655501234"));
    HAS("store error");
    HASNT("not a subscriber");
    TEST_ASSERT_EQUAL_INT(1, run("sub disable +883160655501234"));
    HAS("store error");
    HASNT("no such");

    exec("UPDATE network SET sk_enc = zeroblob(61)");
    TEST_ASSERT_EQUAL_INT(1, run("net init"));
    HAS("store error");
    HASNT("exists already");
    TEST_ASSERT_EQUAL_INT(1, run("status"));
    HAS("network key 1 (store error: can't be read)");

    exec("DROP TABLE cell");
    TEST_ASSERT_EQUAL_INT(1, run("cell add 2 benchB"));
    HAS("store error");
    HASNT("exists already");
    TEST_ASSERT_EQUAL_INT(1, run("cell mode 1 part97"));
    HAS("store error");
    HASNT("no cell");
    TEST_ASSERT_EQUAL_INT(1, run("cell revoke 1"));
    HAS("store error");
    TEST_ASSERT_EQUAL_INT(1, run("status"));
    HAS("store error");

    /* every command is audited, refusals and failures too */
    TEST_ASSERT_EQUAL_INT(0, run("audit 3"));
    HAS("u1000 (refused) status");
    HAS("u1000 (refused) cell revoke 1");
    HAS("u1000 (refused) cell mode 1 part97");
    done();
}

/* A stored list that can't be read is not followed blindly (its version
 * could go backwards): refused, and replaced only with --force. */
static void test_an_unreadable_list_is_replaced_only_with_force(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("net init"));
    TEST_ASSERT_EQUAL_INT(0, run("list set 3 917.25"));
    HAS("list 3: version 1, 917.25");
    exec("UPDATE chan_list SET entries = zeroblob(3)");
    TEST_ASSERT_EQUAL_INT(1, run("list set 3 922.25"));
    HAS("list 3 can't be read");
    HAS("--force");
    TEST_ASSERT_EQUAL_INT(1, run("list show"));
    HAS("list 3: can't be read (store error)");
    TEST_ASSERT_EQUAL_INT(0, run("list set 3 922.25:fixed --force"));
    HAS("list 3: version 2, 922.25:fixed");
    TEST_ASSERT_EQUAL_INT(0, run("list show"));
    HAS("list 3: version 2, 922.25:fixed");
    TEST_ASSERT_EQUAL_INT(0, run("list set 3 none --force")); /* readable: as set */
    HAS("list 3: version 3, (empty)");
    TEST_ASSERT_EQUAL_INT(2, run("list set 3 917.25 --frce"));
    TEST_ASSERT_EQUAL_INT(2, run("list set 3"));
    done();
}

/* Not a command: audited too, and a peer's control characters don't reach
 * the audit text as they are. */
static void test_usage_is_audited_and_detail_is_clean(void)
{
    world();
    char w0[] = "sub", w1[] = "frob\nnicate\x1b[2J";
    char *argv[] = { w0, w1 };
    TEST_ASSERT_EQUAL_INT(2, oc_admin_run(&adm, 2, argv, &out));
    TEST_ASSERT_EQUAL_INT(2, run("frobnicate"));
    HAS("commands: status");
    TEST_ASSERT_EQUAL_INT(0, run("audit 2"));
    HAS("u1000 (usage) frobnicate");
    HAS("u1000 (usage) sub frob?nicate?[2J");
    HASNT("\x1b");
    done();
}

/* Import: a network key that is there but can't be read is a store error,
 * never "not there" (it would be written over); no key material is shown. */
static void test_import_tells_a_store_error_and_shows_no_keys(void)
{
    char cmd[128];
    world();
    write_hss("", 1);
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(0, run(cmd));
    HASNT("404142434445"); /* sk */
    HASNT("0102030405060708"); /* K */
    HASNT("1112131415161718"); /* OPc */
    HASNT("00112233445566778899"); /* token secret */
    TEST_ASSERT_EQUAL_INT(0, run("audit 1"));
    HAS("ADMIN");
    HAS("u1000 import-ocb-hss /tmp/oc_admin_hss_");
    done();

    world();
    TEST_ASSERT_EQUAL_INT(0, run("net init"));
    exec("UPDATE network SET sk_enc = zeroblob(61)");
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS("store error");
    HASNT("imported\n");
    TEST_ASSERT_EQUAL_INT(0, run("sub list"));
    TEST_ASSERT_EQUAL_size_t(0, out.n);
    unlink(hss);
    done();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a_store_error_is_never_none_or_exists);
    RUN_TEST(test_an_unreadable_list_is_replaced_only_with_force);
    RUN_TEST(test_usage_is_audited_and_detail_is_clean);
    RUN_TEST(test_import_tells_a_store_error_and_shows_no_keys);
    RUN_TEST(test_first_setup_and_subscribers);
    RUN_TEST(test_issue_and_disable);
    RUN_TEST(test_channel_lists);
    RUN_TEST(test_import_keeps_activated_terminals);
    RUN_TEST(test_import_is_all_or_nothing);
    return UNITY_END();
}
