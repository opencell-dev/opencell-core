#define _GNU_SOURCE
#include "oc_admin.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "oc_phy.h"
#include "oc_sig_keys.h"
#include "oc_sig_qr.h"
#include "oc_log.h"

/* ---- output ---- */

/* Room for n more bytes and a NUL: 0, or -1 with b->err set. */
static int buf_room(oc_buf_t *b, size_t n)
{
    if (n > SIZE_MAX / 4u - b->n) {
        b->err = 1;
        return -1;
    }
    if (b->n + n + 1u > b->cap) {
        size_t cap = (b->cap == 0 ? 1024u : b->cap);
        while (cap < b->n + n + 1u) cap *= 2u;
        char *p = malloc(cap); /* not realloc: the old buffer (an activation code, say) is wiped first */
        if (p == NULL) {
            b->err = 1; /* the caller must not take a cut output for a whole one */
            return -1;
        }
        if (b->p != NULL) {
            memcpy(p, b->p, b->n + 1u);
            oc_sig_wipe(b->p, b->cap);
            free(b->p);
        }
        b->p = p;
        b->cap = cap;
    }
    return 0;
}

void oc_buf_printf(oc_buf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        b->err = 1;
        return;
    }
    if (buf_room(b, (size_t)n) != 0) return;
    va_start(ap, fmt);
    vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    b->n += (size_t)n;
}

void oc_buf_add(oc_buf_t *b, const void *data, size_t n)
{
    if (buf_room(b, n) != 0) return;
    memcpy(b->p + b->n, data, n);
    b->n += n;
    b->p[b->n] = '\0';
}

void oc_buf_free(oc_buf_t *b)
{
    if (b->p != NULL) oc_sig_wipe(b->p, b->cap);
    free(b->p);
    memset(b, 0, sizeof(*b));
}

/* ---- helpers ---- */

static const char USAGE[] =
    "commands: status | net init [--period S] | cell add ID NAME [--mode part15|part97] [--list N]\n"
    "  | cell mode ID part15|part97 | cell revoke ID | cell cert ID FPR|none | cell list | sub add [NUMBER]\n"
    "  | sub issue NUMBER [--valid-h H] | sub disable NUMBER | sub enable NUMBER | sub release NUMBER\n"
    "  | sub list | loc | cdr [N] | audit [N]\n"
    "  | list set ID MHZ[:fixed],...|none [--force] | list show | import-ocb-hss FILE (--offline only)\n"
    "list set --force: replace a stored list that can't be read (a damaged row), at the version after\n"
    "  the last one written, so every cell of the group takes it\n";

static oc_core_store_t store(oc_admin_t *a) { return oc_sql_store(a->sql); }

static uint64_t now_us(oc_admin_t *a)
{
    if (a->now_us != NULL) return a->now_us();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int o_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    (void)link;
    (void)m;
    return -1; /* offline: no cell has a link */
}
static void o_random(void *c, uint8_t *out, size_t n) { ((oc_admin_t *)c)->random(out, n); }
static uint32_t o_unix(void *c)
{
    (void)c;
    return (uint32_t)time(NULL);
}

/* Whether the configured network key is there: 0, OC_CORE_STORE_NONE or
 * OC_CORE_STORE_FAILED. Its secret half is wiped at once. */
static int key_state(oc_admin_t *a)
{
    oc_core_netkey_t key;
    oc_core_store_t st = store(a);
    int got = st.netkey_get(st.ctx, a->cfg->key_id, &key);
    oc_sig_wipe(&key, sizeof(key));
    return got;
}

/* The daemon's core, or (offline) one of our own over the same store. */
static oc_core_t *core(oc_admin_t *a, oc_buf_t *out)
{
    if (a->core != NULL) return a->core;
    if (!a->have_own) {
        const oc_core_io_t io = { a, o_send, NULL, o_random, o_unix, oc_log_line };
        oc_core_store_t st = store(a);
        int got = key_state(a);
        if (got == OC_CORE_STORE_NONE) {
            oc_buf_printf(out, "no network key %u in the database: run `oc-core admin --offline ... net init` first\n",
                          a->cfg->key_id);
            return NULL;
        }
        if (got != 0 || oc_core_init(&a->own, &io, &st, a->route, a->cfg) != 0) {
            oc_buf_printf(out, "store error: network key %u can't be read (nothing done)\n", a->cfg->key_id);
            return NULL;
        }
        a->have_own = 1;
    }
    return &a->own;
}

static int number_arg(const char *text, uint8_t out[OC_SIG_NUMBER_LEN], oc_buf_t *o)
{
    if (oc_sig_number_normalize(text, strlen(text), NULL, out) != 0) {
        oc_buf_printf(o, "'%s': not a full OpenCell number (e.g. +883-1-606-555-01234)\n", text);
        return -1;
    }
    return 0;
}

static int home(oc_admin_t *a, const uint8_t n[OC_SIG_NUMBER_LEN])
{
    return oc_core_route_home(a->route, oc_core_route_find(a->route, n));
}

/* The subscriber's state (OC_CORE_SUB_*): 0, OC_CORE_STORE_NONE or
 * OC_CORE_STORE_FAILED. Its K and OPc are wiped at once. */
static int sub_state(oc_admin_t *a, const uint8_t n[OC_SIG_NUMBER_LEN], uint8_t *state)
{
    oc_core_sub_t s;
    oc_core_store_t st = store(a);
    memset(&s, 0, sizeof(s));
    int got = st.sub_get(st.ctx, n, &s);
    *state = s.state;
    oc_sig_wipe(&s, sizeof(s));
    return got;
}

static const char *show(const uint8_t n[OC_SIG_NUMBER_LEN], char out[OC_SIG_NUMBER_TEXT + OC_SIG_NUMBER_SHOW + 4])
{
    char t[OC_SIG_NUMBER_TEXT], f[OC_SIG_NUMBER_SHOW];
    oc_sig_number_to_text(n, t);
    if (oc_sig_number_format(n, f, sizeof(f)) == 0) strcpy(f, t);
    snprintf(out, OC_SIG_NUMBER_TEXT + OC_SIG_NUMBER_SHOW + 4, "%s (%s)", t, f);
    return out;
}

/* The words from argv[from] on are "--flag VALUE" pairs, each flag one of
 * flags (NULL-ended): 0, or -1 (then the command is not one: usage). */
static int opts_ok(int argc, char **argv, int from, const char *const *flags)
{
    for (int i = from; i < argc; i += 2) {
        int known = 0;
        for (const char *const *f = flags; *f != NULL; f++) known |= strcmp(argv[i], *f) == 0;
        if (!known || i + 1 >= argc) return -1;
    }
    return 0;
}

/* "--flag VALUE" as a number lo..hi. 0 not given, 1 given, -1 bad. */
static int opt_num(int argc, char **argv, const char *flag, long lo, long hi, long *v, oc_buf_t *o)
{
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], flag) != 0) continue;
        char *end;
        long x = i + 1 < argc ? strtol(argv[i + 1], &end, 10) : 0;
        if (i + 1 >= argc || *end != '\0' || end == argv[i + 1] || x < lo || x > hi) {
            oc_buf_printf(o, "%s: a number %ld-%ld\n", flag, lo, hi);
            return -1;
        }
        *v = x;
        return 1;
    }
    return 0;
}

static const char *opt_str(int argc, char **argv, const char *flag)
{
    for (int i = 0; i + 1 < argc; i++) {
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    }
    return NULL;
}

static int mode_arg(const char *s, uint8_t *mode, oc_buf_t *o)
{
    if (strcmp(s, "part15") == 0) *mode = OC_SIG_MODE_PART15;
    else if (strcmp(s, "part97") == 0) *mode = OC_SIG_MODE_PART97;
    else {
        oc_buf_printf(o, "mode '%s': part15 or part97\n", s);
        return -1;
    }
    return 0;
}

static const char *mode_name(int m) { return m == OC_SIG_MODE_PART97 ? "part97" : "part15"; }

static int linked(oc_admin_t *a, uint32_t cell_id)
{
    for (unsigned i = 0; a->core != NULL && i < OC_CORE_LINKS; i++) {
        if (a->core->links[i].used && a->core->links[i].cell_id == cell_id) return 1;
    }
    return 0;
}

static sqlite3_stmt *q(oc_admin_t *a, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(oc_sql_db(a->sql), sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return NULL;
    }
    return st;
}

/* One step of a listing: SQLITE_ROW, SQLITE_DONE, or an error (also for a
 * statement that could not be prepared). A listing that does not end in
 * SQLITE_DONE is a store error, not a short list. */
static int step(sqlite3_stmt *st) { return st != NULL ? sqlite3_step(st) : SQLITE_ERROR; }

static long count(oc_admin_t *a, const char *sql)
{
    sqlite3_stmt *st = q(a, sql);
    long n = step(st) == SQLITE_ROW ? (long)sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

static const char *text_col(sqlite3_stmt *st, int col)
{
    const char *t = (const char *)sqlite3_column_text(st, col);
    return t != NULL ? t : "-";
}

static int store_error(oc_buf_t *o, const char *what)
{
    oc_buf_printf(o, "store error: %s\n", what);
    return 1;
}

/* ---- commands ---- */

static int cmd_status(oc_admin_t *a, oc_buf_t *o)
{
    int bad = 0, rc;
    int key = key_state(a);
    bad |= key == OC_CORE_STORE_FAILED;
    oc_buf_printf(o, "core %u, network key %u%s, schema v%d, %s\n", a->cfg->core_id, a->cfg->key_id,
                  key == 0 ? "" : key == OC_CORE_STORE_NONE ? " (missing: net init)" : " (store error: can't be read)",
                  oc_sql_version(a->sql), a->core != NULL ? "running" : "offline");
    int calls = 0, links = 0;
    if (a->core != NULL) {
        for (unsigned i = 0; i < OC_CORE_CALLS; i++) calls += a->core->calls[i].used != 0;
        for (unsigned i = 0; i < OC_CORE_LINKS; i++) links += a->core->links[i].used != 0;
    }
    long subs = count(a, "SELECT count(*) FROM subscriber");
    long act = count(a, "SELECT count(*) FROM subscriber WHERE activated = 1");
    long dis = count(a, "SELECT count(*) FROM subscriber WHERE state = 2");
    long locs = count(a, "SELECT count(*) FROM location");
    if (subs < 0 || act < 0 || dis < 0 || locs < 0) {
        bad = 1;
        oc_buf_printf(o, "store error: subscribers and locations can't be counted; calls %d, links %d\n", calls, links);
    } else {
        oc_buf_printf(o, "subscribers %ld (%ld activated, %ld disabled), locations %ld, calls %d, links %d\n", subs, act,
                      dis, locs, calls, links);
    }
    sqlite3_stmt *s = q(a, "SELECT cell_id, name, mode, enabled, list_id, last_seen FROM cell ORDER BY cell_id");
    while ((rc = step(s)) == SQLITE_ROW) {
        uint32_t id = (uint32_t)sqlite3_column_int64(s, 0);
        long ago = (long)time(NULL) - (long)sqlite3_column_int64(s, 5);
        oc_buf_printf(o, "cell %u \"%s\": %s, %s, list %d, %s", id, text_col(s, 1), mode_name(sqlite3_column_int(s, 2)),
                      sqlite3_column_int(s, 3) ? "enabled" : "revoked", sqlite3_column_int(s, 4),
                      linked(a, id) ? "linked" : "not linked");
        if (sqlite3_column_int64(s, 5) != 0) oc_buf_printf(o, ", last HELLO %ld s ago", ago);
        oc_buf_printf(o, "\n");
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) bad |= store_error(o, "the cells can't be listed");
    if (oc_sql_unseal_failures(a->sql) != 0) {
        oc_buf_printf(o, "WARNING: %u sealed values did not open (damaged rows): their reads fail\n",
                      oc_sql_unseal_failures(a->sql));
    }
    return bad;
}

static int cmd_net(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    static const char *const flags[] = { "--period", NULL };
    long period = 1800;
    if (argc < 2 || strcmp(argv[1], "init") != 0 || opts_ok(argc, argv, 2, flags) != 0) return 2;
    if (opt_num(argc, argv, "--period", 60, 65535, &period, o) < 0) return 1;
    oc_core_store_t st = store(a);
    int got = key_state(a);
    if (got == 0) {
        oc_buf_printf(o, "network key %u exists already: nothing done\n", a->cfg->key_id);
        return 1;
    }
    if (got != OC_CORE_STORE_NONE) return store_error(o, "can't tell whether the network key exists (nothing done)");
    uint8_t r[32];
    a->random(r, sizeof(r));
    int rc = oc_core_netkey_new(&st, a->cfg->key_id, (uint16_t)period, r, (uint32_t)time(NULL));
    oc_sig_wipe(r, sizeof(r));
    if (rc != 0) return store_error(o, "the network key was not stored");
    oc_buf_printf(o, "network key %u made, registration period %ld s\n", a->cfg->key_id, period);
    return 0;
}

static int cmd_cell(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    static const char *const add_flags[] = { "--mode", "--list", NULL };
    oc_core_t *k;
    oc_core_store_t st = store(a);
    oc_core_cell_t c;
    char *end;
    if (argc == 2 && strcmp(argv[1], "list") == 0) return cmd_status(a, o);
    int add = argc >= 4 && strcmp(argv[1], "add") == 0 && opts_ok(argc, argv, 4, add_flags) == 0;
    int mode = argc == 4 && strcmp(argv[1], "mode") == 0;
    int revoke = argc == 3 && strcmp(argv[1], "revoke") == 0;
    int cert = argc == 4 && strcmp(argv[1], "cert") == 0;
    if (!add && !mode && !revoke && !cert) return 2;
    unsigned long id = strtoul(argv[2], &end, 10);
    if (*end != '\0' || end == argv[2] || argv[2][0] == '-' || id == 0 || id > 0xFFFFFFFFul) {
        oc_buf_printf(o, "cell id '%s': 1-4294967295\n", argv[2]);
        return 1;
    }
    if (add) {
        uint8_t m = OC_SIG_MODE_PART15;
        long list = 0;
        const char *ms = opt_str(argc, argv, "--mode");
        if ((ms != NULL && mode_arg(ms, &m, o) != 0) || opt_num(argc, argv, "--list", 0, 65535, &list, o) < 0) return 1;
        int ok = strlen(argv[3]) < sizeof(c.name) && argv[3][0] != '-';
        if (ok) {
            char name[sizeof(c.name)];
            snprintf(name, sizeof(name), "%s", argv[3]);
            ok = !oc_log_clean(name);
        }
        if (!ok) {
            oc_buf_printf(o, "cell name '%s': 1-%zu printable characters\n", argv[3], sizeof(c.name) - 1u);
            return 1;
        }
        if ((k = core(a, o)) == NULL) return 1;
        int r = oc_core_cell_add(k, (uint32_t)id, argv[3], m, (uint16_t)list);
        if (r == -1) {
            oc_buf_printf(o, "cell %lu exists already: nothing changed\n", id);
            return 1;
        }
        if (r != 0) return store_error(o, "the cell was not added");
        oc_buf_printf(o, "cell %lu \"%s\" added: %s, list %ld\n", id, argv[3], mode_name(m), list);
        return 0;
    }
    int got = st.cell_get(st.ctx, (uint32_t)id, &c);
    if (got == OC_CORE_STORE_NONE) {
        oc_buf_printf(o, "no cell %lu\n", id);
        return 1;
    }
    if (got != 0) return store_error(o, "the cell can't be read (nothing changed)");
    if (cert) {
        char fpr[65];
        int none = strcmp(argv[3], "none") == 0;
        if (!none && oc_admin_fpr(argv[3], fpr) != 0) {
            oc_buf_printf(o, "fingerprint '%s': the certificate's SHA-256, 64 hex digits (oc-ca prints it), or none\n",
                          argv[3]);
            return 1;
        }
        if (!none && !c.enabled) {
            oc_buf_printf(o, "cell %lu is revoked: nothing pinned\n", id);
            return 1;
        }
        if (oc_sql_cell_cert_set(a->sql, (uint32_t)id, none ? NULL : fpr) != 0) {
            return store_error(o, "the fingerprint was not stored");
        }
        oc_buf_printf(o, "cell %lu: %s\n", id, none ? "no certificate pinned" : "certificate pinned");
        return 0;
    }
    if (mode) {
        if (mode_arg(argv[3], &c.mode, o) != 0) return 1;
        if (!c.enabled) {
            oc_buf_printf(o, "cell %lu is revoked: nothing changed\n", id);
            return 1;
        }
        if (st.cell_put(st.ctx, &c) != 0) return store_error(o, "the mode was not stored");
        if (a->drop_cell != NULL && linked(a, (uint32_t)id)) {
            a->drop_cell(a->ctx, (uint32_t)id);
            oc_buf_printf(o, "cell %lu: %s; its link was dropped, it takes the mode when it reconnects\n", id, argv[3]);
        } else {
            oc_buf_printf(o, "cell %lu: %s, from its next HELLO\n", id, argv[3]);
        }
        return 0;
    }
    if (!c.enabled) { /* unpinned again: an earlier revoke may have failed between the two writes */
        if (oc_sql_cell_cert_set(a->sql, (uint32_t)id, NULL) != 0) return store_error(o, "the pin was not removed");
        oc_buf_printf(o, "cell %lu is revoked already: nothing changed\n", id);
        return 0;
    }
    if ((k = core(a, o)) == NULL) return 1;
    if (oc_core_cell_revoke(k, (uint32_t)id, now_us(a)) != 0) return store_error(o, "the cell was not revoked");
    if (oc_sql_cell_cert_set(a->sql, (uint32_t)id, NULL) != 0) {
        return store_error(o, "the cell is revoked, but its certificate is still pinned: run this again");
    }
    oc_buf_printf(o, "cell %lu revoked: its link is dropped, its HELLO refused and its certificate unpinned\n", id);
    return 0;
}

int oc_admin_fpr(const char *text, char out[65])
{
    if (strlen(text) != 64) return -1;
    for (int i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)text[i])) return -1;
        out[i] = (char)tolower((unsigned char)text[i]);
    }
    out[64] = '\0';
    return 0;
}

static int cmd_sub(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    static const char *const issue_flags[] = { "--valid-h", NULL };
    oc_core_t *k;
    uint8_t n[OC_SIG_NUMBER_LEN], got[OC_SIG_NUMBER_LEN], state = 0;
    char sh[OC_SIG_NUMBER_TEXT + OC_SIG_NUMBER_SHOW + 4];
    int rc;
    if (argc < 2) return 2;
    if (strcmp(argv[1], "list") == 0 && argc == 2) {
        sqlite3_stmt *s = q(a, "SELECT number, state, activated, tmid, sqn FROM subscriber ORDER BY number");
        while ((rc = step(s)) == SQLITE_ROW) {
            oc_buf_printf(o, "%s  %s  %s  tmid %08x  sqn %lld\n", text_col(s, 0),
                          sqlite3_column_int(s, 1) == OC_CORE_SUB_DISABLED ? "disabled" : "active  ",
                          sqlite3_column_int(s, 2) ? "activated    " : "not activated",
                          (unsigned)sqlite3_column_int64(s, 3), (long long)sqlite3_column_int64(s, 4));
        }
        sqlite3_finalize(s);
        return rc == SQLITE_DONE ? 0 : store_error(o, "the subscribers can't be listed");
    }
    if (strcmp(argv[1], "add") == 0 && argc <= 3) {
        if (argc == 3) {
            if (number_arg(argv[2], n, o) != 0) return 1;
            memcpy(a->audit_number, n, OC_SIG_NUMBER_LEN);
            if (!home(a, n) || oc_core_number_reserved(n)) {
                oc_buf_printf(o, "%s: not in a block this core is home for, or reserved\n", show(n, sh));
                return 1;
            }
        }
        if ((k = core(a, o)) == NULL) return 1;
        if (argc == 3) {
            int g = sub_state(a, n, &state);
            if (g == 0) {
                oc_buf_printf(o, "%s: already a subscriber\n", show(n, sh));
                return 1;
            }
            if (g != OC_CORE_STORE_NONE) return store_error(o, "the number's record can't be read (nothing added)");
        }
        if (oc_core_sub_add(k, argc == 3 ? n : NULL, got) != 0) {
            if (argc == 3) return store_error(o, "the subscriber was not added");
            oc_buf_printf(o, "no number picked: no NANP block this core is home for, no free number found, "
                             "or a store error\n");
            return 1;
        }
        memcpy(a->audit_number, got, OC_SIG_NUMBER_LEN);
        oc_buf_printf(o, "subscriber %s added\n", show(got, sh));
        return 0;
    }
    int issue = argc >= 3 && strcmp(argv[1], "issue") == 0 && opts_ok(argc, argv, 3, issue_flags) == 0;
    int disable = argc == 3 && strcmp(argv[1], "disable") == 0;
    int enable = argc == 3 && strcmp(argv[1], "enable") == 0;
    int release = argc == 3 && strcmp(argv[1], "release") == 0;
    if (!issue && !disable && !enable && !release) return 2;
    if (number_arg(argv[2], n, o) != 0) return 1;
    memcpy(a->audit_number, n, OC_SIG_NUMBER_LEN);
    if (enable || release) {
        char why[16];
        snprintf(why, sizeof(why), "u%u", a->uid);
        if ((k = core(a, o)) == NULL) return 1;
        int r = enable ? oc_core_sub_enable(k, n) : oc_core_sub_release(k, n, why);
        if (r == OC_CORE_E_NOT_FOUND) {
            oc_buf_printf(o, "%s: not a subscriber (no such subscriber)\n", show(n, sh));
            return 1;
        }
        if (r == OC_CORE_E_ACTIVATED) {
            oc_buf_printf(o, "%s is activated: only an unactivated number is released (sub disable stops it)\n",
                          show(n, sh));
            return 1;
        }
        if (r != 0) return store_error(o, enable ? "the subscriber was not enabled" : "the number was not released");
        oc_buf_printf(o, "%s %s\n", show(n, sh), enable ? "enabled: it may register again" : "released: it is free");
        return 0;
    }
    long hours = 24;
    if (issue && opt_num(argc, argv, "--valid-h", 1, 720, &hours, o) < 0) return 1;
    if (issue && !home(a, n)) {
        oc_buf_printf(o, "%s: not in a block this core is home for\n", show(n, sh));
        return 1;
    }
    if ((k = core(a, o)) == NULL) return 1;
    int g = sub_state(a, n, &state);
    if (g == OC_CORE_STORE_NONE) {
        oc_buf_printf(o, "%s: not a subscriber (no such subscriber)\n", show(n, sh));
        return 1;
    }
    if (g != 0) return store_error(o, "the subscriber can't be read (nothing changed)");
    if (issue) {
        oc_sig_qr_t qr;
        char text[OC_SIG_QR_TEXT + 1];
        if (state != OC_CORE_SUB_ACTIVE) {
            oc_buf_printf(o, "%s is disabled: no code issued\n", show(n, sh));
            return 1;
        }
        if (oc_core_token_issue(k, n, (uint32_t)hours * 3600u, &qr) != 0) return store_error(o, "no code issued");
        size_t len = oc_sig_qr_format(&qr, text, sizeof(text));
        oc_sig_wipe(&qr, sizeof(qr));
        if (len == 0) {
            oc_sig_wipe(text, sizeof(text));
            return store_error(o, "the code could not be formatted");
        }
        oc_buf_printf(o, "activation code for %s, valid %ld h (any older unused code is void):\n%s\n", show(n, sh),
                      hours, text);
        oc_sig_wipe(text, sizeof(text));
        return 0;
    }
    if (state == OC_CORE_SUB_DISABLED) {
        oc_buf_printf(o, "%s is already disabled: nothing changed\n", show(n, sh));
        return 0;
    }
    if (oc_core_sub_disable(k, n, now_us(a)) != 0) return store_error(o, "the subscriber was not disabled");
    oc_buf_printf(o, "%s disabled: its codes are void and its cell was told\n", show(n, sh));
    return 0;
}

static int cmd_loc(oc_admin_t *a, oc_buf_t *o)
{
    int rc;
    sqlite3_stmt *s = q(a, "SELECT number, cell_id, tmid, expires FROM location ORDER BY number");
    long now = (long)time(NULL);
    while ((rc = step(s)) == SQLITE_ROW) {
        long left = (long)sqlite3_column_int64(s, 3) - now;
        oc_buf_printf(o, "%s  cell %u  tmid %08x  ", text_col(s, 0), (unsigned)sqlite3_column_int64(s, 1),
                      (unsigned)sqlite3_column_int64(s, 2));
        if (left > 0) oc_buf_printf(o, "expires in %ld s\n", left);
        else oc_buf_printf(o, "expired\n");
    }
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? 0 : store_error(o, "the locations can't be listed");
}

static long last_n(int argc, char **argv, oc_buf_t *o)
{
    char *end;
    if (argc < 2) return 20;
    long n = strtol(argv[1], &end, 10);
    if (*end != '\0' || end == argv[1] || n < 1 || n > 10000) {
        oc_buf_printf(o, "'%s': a count 1-10000\n", argv[1]);
        return -1;
    }
    return n;
}

static int cmd_cdr(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    int rc;
    long n = last_n(argc, argv, o);
    if (n < 0) return 1;
    sqlite3_stmt *s = q(a, "SELECT id, caller, called, cell_a, cell_b, setup, answer, \"end\", cause FROM cdr"
                           " ORDER BY id DESC LIMIT ?");
    if (s != NULL && sqlite3_bind_int64(s, 1, n) != SQLITE_OK) {
        sqlite3_finalize(s);
        s = NULL;
    }
    while ((rc = step(s)) == SQLITE_ROW) {
        long setup = (long)sqlite3_column_int64(s, 5), ans = (long)sqlite3_column_int64(s, 6);
        long end = (long)sqlite3_column_int64(s, 7);
        oc_buf_printf(o, "#%lld %s -> %s  cells %u -> %u  %s, %ld s, cause %d\n", (long long)sqlite3_column_int64(s, 0),
                      text_col(s, 1), text_col(s, 2), (unsigned)sqlite3_column_int64(s, 3),
                      (unsigned)sqlite3_column_int64(s, 4), ans != 0 ? "answered" : "not answered",
                      end > setup ? end - setup : 0, sqlite3_column_int(s, 8));
    }
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? 0 : store_error(o, "the call records can't be listed");
}

static const char *event_name(int e)
{
    static const char *const names[] = { "?",           "ACTIVATE",    "ACT_FAIL",   "REGISTER",
                                         "AUTH_FAIL",   "RESYNC",      "LOC_CANCEL", "TOKEN_ISSUE",
                                         "SUB_DISABLE", "CELL_REJECT", "ADMIN",       "API",
                                         "SUB_RELEASE", "SUB_ENABLE" };
    return e >= 0 && e < (int)(sizeof(names) / sizeof(names[0])) ? names[e] : "?";
}

static int cmd_audit(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    int rc;
    long n = last_n(argc, argv, o);
    if (n < 0) return 1;
    sqlite3_stmt *s = q(a, "SELECT ts, event, number, tmid, cell_id, detail FROM audit ORDER BY id DESC LIMIT ?");
    if (s != NULL && sqlite3_bind_int64(s, 1, n) != SQLITE_OK) {
        sqlite3_finalize(s);
        s = NULL;
    }
    while ((rc = step(s)) == SQLITE_ROW) {
        time_t ts = (time_t)sqlite3_column_int64(s, 0);
        char when[32] = "?";
        struct tm tm;
        if (gmtime_r(&ts, &tm) != NULL) strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &tm);
        oc_buf_printf(o, "%s  %-11s  %s  tmid %08x  cell %u  %s\n", when, event_name(sqlite3_column_int(s, 1)),
                      text_col(s, 2), (unsigned)sqlite3_column_int64(s, 3), (unsigned)sqlite3_column_int64(s, 4),
                      text_col(s, 5));
    }
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? 0 : store_error(o, "the audit log can't be listed");
}

static void list_line(oc_buf_t *o, long id, const oc_sig_chan_list_t *l)
{
    oc_buf_printf(o, "list %ld: version %u,", id, l->ver);
    for (uint8_t i = 0; i < l->count; i++) {
        oc_buf_printf(o, " %u.%02u%s", (unsigned)(l->freq_hz[i] / 1000000u), (unsigned)(l->freq_hz[i] % 1000000u / 10000u),
                      (l->flags[i] & OC_SIG_CHAN_FIXED) ? ":fixed" : "");
    }
    oc_buf_printf(o, "%s\n", l->count == 0 ? " (empty)" : "");
}

static int cmd_list(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    oc_core_store_t st = store(a);
    oc_sig_chan_list_t l, cur;
    char err[128], *end, *w[4];
    int nw = 0, force = 0, rc, bad = 0;
    for (int i = 0; i < argc; i++) { /* the words, and --force wherever it is */
        if (strcmp(argv[i], "--force") == 0) force++;
        else if (nw < 4) w[nw++] = argv[i];
        else return 2;
    }
    if (nw == 2 && !force && strcmp(w[1], "show") == 0) {
        sqlite3_stmt *s = q(a, "SELECT list_id FROM chan_list ORDER BY list_id");
        while ((rc = step(s)) == SQLITE_ROW) {
            long id = (long)sqlite3_column_int64(s, 0);
            int got = st.list_get(st.ctx, (uint16_t)id, &l);
            if (got == 0) {
                list_line(o, id, &l);
            } else if (got != OC_CORE_STORE_NONE) {
                oc_buf_printf(o, "list %ld: can't be read (store error); `list set %ld ... --force` replaces it\n", id,
                              id);
                bad = 1;
            }
        }
        sqlite3_finalize(s);
        if (rc != SQLITE_DONE) bad |= store_error(o, "the channel lists can't be listed");
        return bad;
    }
    if (nw != 4 || force > 1 || strcmp(w[1], "set") != 0) return 2;
    long id = strtol(w[2], &end, 10);
    if (*end != '\0' || end == w[2] || id < 1 || id > 65535) {
        oc_buf_printf(o, "list id '%s': 1-65535\n", w[2]);
        return 1;
    }
    if (oc_chan_parse(w[3], &l, err, sizeof(err)) != 0) {
        oc_buf_printf(o, "%s\n", err);
        return 1;
    }
    oc_core_t *k = core(a, o);
    if (k == NULL) return 1;
    if (!force && st.list_get(st.ctx, (uint16_t)id, &cur) == OC_CORE_STORE_FAILED) {
        oc_buf_printf(o, "store error: list %ld can't be read, so the version after it is unknown: nothing changed.\n"
                         "`list set %ld %s --force` replaces it, after the last version written\n",
                      id, id, w[3]);
        return 1;
    }
    int ver = force ? oc_core_chan_list_replace(k, (uint16_t)id, &l, now_us(a))
                    : oc_core_chan_list_set(k, (uint16_t)id, &l, now_us(a));
    if (ver < 0) return store_error(o, "the list was not changed");
    l.ver = (uint8_t)ver;
    list_line(o, id, &l);
    return 0;
}

/* "917.25" -> 917250000 exactly: at most 3 decimals. */
static int parse_mhz(const char *s, size_t len, uint32_t *hz)
{
    uint32_t whole = 0, frac = 0, scale = 1000000u;
    size_t i = 0;
    if (len == 0) return -1;
    for (; i < len && s[i] != '.'; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        whole = whole * 10u + (uint32_t)(s[i] - '0');
        if (whole > 999u) return -1;
    }
    if (i < len) {
        if (++i == len || len - i > 3) return -1;
        for (; i < len; i++) {
            if (s[i] < '0' || s[i] > '9') return -1;
            scale /= 10u;
            frac += (uint32_t)(s[i] - '0') * scale;
        }
    }
    *hz = whole * 1000000u + frac;
    return 0;
}

int oc_chan_parse(const char *text, oc_sig_chan_list_t *out, char *err, size_t cap)
{
    memset(out, 0, sizeof(*out));
    if (text[0] == '\0' || strcmp(text, "none") == 0) return 0;
    for (const char *c = text; *c != '\0'; c++) {
        if (isspace((unsigned char)*c)) {
            snprintf(err, cap, "'%s': no spaces (e.g. 917.25,922.25:fixed)", text);
            return -1;
        }
    }
    const char *p = text;
    for (;;) {
        const char *end = strchr(p, ',');
        size_t len = end != NULL ? (size_t)(end - p) : strlen(p), num = len;
        uint8_t flags = 0;
        const char *colon = memchr(p, ':', len);
        if (colon != NULL) {
            num = (size_t)(colon - p);
            if (len - num != 6 || strncmp(colon, ":fixed", 6) != 0) {
                snprintf(err, cap, "'%.*s': only ':fixed' may follow a frequency", (int)len, p);
                return -1;
            }
            flags = OC_SIG_CHAN_FIXED;
        }
        uint32_t hz;
        if (parse_mhz(p, num, &hz) != 0 || oc_channel_of_freq(OC_BAND_915, hz) == OC_INVALID_CHANNEL) {
            snprintf(err, cap, "'%.*s' is not a 915 grid channel (902.25-927.75 MHz, 0.5 MHz steps)", (int)num, p);
            return -1;
        }
        for (uint8_t i = 0; i < out->count; i++) {
            if (out->freq_hz[i] == hz) {
                snprintf(err, cap, "'%.*s': %u.%02u MHz twice", (int)len, p, (unsigned)(hz / 1000000u),
                         (unsigned)(hz % 1000000u / 10000u));
                return -1;
            }
        }
        if (out->count == OC_SIG_CHAN_MAX) {
            snprintf(err, cap, "more than %u entries", OC_SIG_CHAN_MAX);
            return -1;
        }
        out->freq_hz[out->count] = hz;
        out->flags[out->count++] = flags;
        if (end == NULL) return 0;
        p = end + 1;
    }
}

/* ---- dispatch and audit ---- */

/* The record of one command: "u<uid> [(sudo u<uid>)] [(refused)|(usage)]
 * <words>", cut to the detail's size, a peer's control characters shown as
 * '?' (oc_log_clean),
 * with the subscriber's number in its own column when the command named or
 * picked one. */
static void audit(oc_admin_t *a, int argc, char **argv, int rc, oc_buf_t *out)
{
    oc_core_audit_t r;
    oc_core_store_t st = store(a);
    memset(&r, 0, sizeof(r));
    r.ts = (uint32_t)time(NULL);
    r.event = OC_CORE_AUDIT_ADMIN;
    memcpy(r.number, a->audit_number, OC_SIG_NUMBER_LEN); /* all zero: none (NULL in the column) */
    int n = snprintf(r.detail, sizeof(r.detail), "u%u", a->uid);
    if (a->sudo_uid != 0) n += snprintf(r.detail + n, sizeof(r.detail) - (size_t)n, " (sudo u%u)", a->sudo_uid);
    n += snprintf(r.detail + n, sizeof(r.detail) - (size_t)n, "%s", rc == 0 ? "" : rc == 2 ? " (usage)" : " (refused)");
    for (int i = 0; i < argc && n > 0 && (size_t)n < sizeof(r.detail); i++) {
        n += snprintf(r.detail + n, sizeof(r.detail) - (size_t)n, " %s", argv[i]);
    }
    oc_log_clean(r.detail);
    if (st.audit_add(st.ctx, &r) != 0) {
        oc_log(OC_LOG_ERR, "admin: audit write FAILED");
        oc_buf_printf(out, "WARNING: store error: this command's audit record was not written\n");
    }
}

int oc_admin_sudo_field(const char *word, uint32_t peer_uid, uint32_t *sudo_uid)
{
    static const char F[] = OC_ADMIN_SUDO_FIELD;
    if (strncmp(word, "--", 2) != 0) return 0;
    if (strncmp(word, F, sizeof(F) - 1u) != 0 || peer_uid != 0) return -1;
    const char *d = word + sizeof(F) - 1u;
    size_t n = strlen(d);
    if (n < 1u || n > 10u || d[0] == '0') return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (d[i] < '0' || d[i] > '9') return -1;
        v = v * 10u + (uint64_t)(d[i] - '0');
    }
    if (v > 0xffffffffu) return -1;
    *sudo_uid = (uint32_t)v;
    return 1;
}

int oc_admin_run(oc_admin_t *a, int argc, char **argv, oc_buf_t *out)
{
    int rc = 2;
    const char *c = argc >= 1 ? argv[0] : "";
    memset(a->audit_number, 0, sizeof(a->audit_number));
    if (strcmp(c, "status") == 0 && argc == 1) rc = cmd_status(a, out);
    else if (strcmp(c, "net") == 0) rc = cmd_net(a, argc, argv, out);
    else if (strcmp(c, "cell") == 0) rc = cmd_cell(a, argc, argv, out);
    else if (strcmp(c, "sub") == 0) rc = cmd_sub(a, argc, argv, out);
    else if (strcmp(c, "loc") == 0 && argc == 1) rc = cmd_loc(a, out);
    else if (strcmp(c, "cdr") == 0 && argc <= 2) rc = cmd_cdr(a, argc, argv, out);
    else if (strcmp(c, "audit") == 0 && argc <= 2) rc = cmd_audit(a, argc, argv, out);
    else if (strcmp(c, "list") == 0) rc = cmd_list(a, argc, argv, out);
    else if (strcmp(c, "import-ocb-hss") == 0 && argc == 2) rc = oc_import_ocb_hss(a, argv[1], out);
    if (rc == 2) oc_buf_printf(out, "%s", USAGE);
    if (out->err) { /* the output is cut: `sub issue` must not look done with no code shown */
        rc = 1;
        oc_buf_printf(out, "\nout of memory: this output is incomplete (a code not shown can be issued again)\n");
    }
    audit(a, argc, argv, rc, out);
    return rc;
}
