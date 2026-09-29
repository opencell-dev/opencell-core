#define _GNU_SOURCE
/* import-ocb-hss: ocbench's text HSS into the core's database. The file's
 * lines (ocb_hss.h, as ocbench wrote them):
 *   network key_id=1 sk=<64 hex> pk=<64 hex> mode=part15 period=1800
 *   sub number=+883160655501234 token_id=<16 hex> token_secret=<32 hex> expiry=<unix s>
 *       used=0|1 tmid=<8 hex> activated=0|1 k=<32 hex> opc=<32 hex> sqn=<12 hex>   (one line)
 * The file must be a regular file of at most 64 KiB. It is read with
 * read(2) into one buffer of our own - no stdio, whose buffer would keep a
 * copy of the keys we could not wipe - and that buffer, the line being
 * parsed and the parsed records are wiped on every path. The keys (SKn, K,
 * OPc) go into the store, which seals them, and nowhere else: no message
 * names them. The write lock is taken first (BEGIN IMMEDIATE), then
 * everything is checked, then written, then committed: the checks and the
 * writes are one transaction. A store that can't answer refuses the import
 * (a network key there but unreadable must not be written over). */
#include "oc_admin.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "oc_sig_crypto.h"
#include "oc_sig_keys.h"

#define IMPORT_SUBS 64u
#define IMPORT_MAX  (64u * 1024u) /* bytes: ocbench's 16 subscribers take ~4 KiB */
#define IMPORT_LINE 512u

typedef struct {
    uint8_t  number[OC_SIG_NUMBER_LEN];
    uint32_t tmid;
    int      activated;
    uint8_t  k[16], opc[16], sqn[6];
} imp_sub_t;

typedef struct {
    int       have_net;
    uint16_t  key_id, period;
    uint8_t   sk[32], pk[32];
    imp_sub_t sub[IMPORT_SUBS];
    unsigned  n;
} imp_t;

static int hex(const char *s, uint8_t *b, size_t n)
{
    if (strlen(s) != 2u * n) return -1;
    for (size_t i = 0; i < 2u * n; i++) {
        if (!isxdigit((unsigned char)s[i])) return -1;
    }
    for (size_t i = 0; i < n; i++) {
        char two[3] = { s[2u * i], s[2u * i + 1u], '\0' };
        b[i] = (uint8_t)strtoul(two, NULL, 16);
    }
    return 0;
}

static int num(const char *s, unsigned long max, unsigned long *out, int base)
{
    char *end;
    errno = 0;
    if (*s == '\0') return -1;
    for (const char *c = s; *c != '\0'; c++) { /* digits only: no sign, space or 0x */
        if (base == 16 ? !isxdigit((unsigned char)*c) : !isdigit((unsigned char)*c)) return -1;
    }
    unsigned long v = strtoul(s, &end, base);
    if (errno != 0 || *end != '\0' || v > max) return -1;
    *out = v;
    return 0;
}

/* One line's fields: NULL, or why the line is refused. */
static const char *parse_line(imp_t *m, char *kind, char *save)
{
    static const char BAD[] = "not an ocbench HSS line";
    unsigned seen = 0, want, bit;
    unsigned long v;
    imp_sub_t s;
    const char *ret = BAD;
    memset(&s, 0, sizeof(s));
    int net = strcmp(kind, "network") == 0;
    if (!net && strcmp(kind, "sub") != 0) return BAD;
    for (char *tok = strtok_r(NULL, " \t\n", &save); tok != NULL; tok = strtok_r(NULL, " \t\n", &save)) {
        char *val = strchr(tok, '=');
        if (val == NULL) goto done;
        *val++ = '\0';
        if (net && strcmp(tok, "key_id") == 0 && num(val, 65535, &v, 10) == 0) m->key_id = (uint16_t)v, bit = 1;
        else if (net && strcmp(tok, "sk") == 0 && hex(val, m->sk, 32) == 0) bit = 2;
        else if (net && strcmp(tok, "pk") == 0 && hex(val, m->pk, 32) == 0) bit = 4;
        else if (net && strcmp(tok, "mode") == 0 && (strcmp(val, "part15") == 0 || strcmp(val, "part97") == 0)) bit = 8;
        else if (net && strcmp(tok, "period") == 0 && num(val, 65535, &v, 10) == 0 && v >= 60)
            m->period = (uint16_t)v, bit = 16;
        else if (!net && strcmp(tok, "number") == 0 && oc_sig_number_to_bcd(val, strlen(val), s.number) == 0) bit = 1;
        else if (!net && strcmp(tok, "tmid") == 0 && strlen(val) == 8 && num(val, 0xFFFFFFFFul, &v, 16) == 0)
            s.tmid = (uint32_t)v, bit = 2;
        else if (!net && strcmp(tok, "activated") == 0 && num(val, 1, &v, 10) == 0) s.activated = (int)v, bit = 4;
        else if (!net && strcmp(tok, "k") == 0 && hex(val, s.k, 16) == 0) bit = 8;
        else if (!net && strcmp(tok, "opc") == 0 && hex(val, s.opc, 16) == 0) bit = 16;
        else if (!net && strcmp(tok, "sqn") == 0 && hex(val, s.sqn, 6) == 0) bit = 32;
        /* the token is not carried over (its id has no block index, spec §14.3) */
        else if (!net && strcmp(tok, "token_id") == 0) bit = 64;
        else if (!net && strcmp(tok, "token_secret") == 0) bit = 128;
        else if (!net && strcmp(tok, "expiry") == 0) bit = 256;
        else if (!net && strcmp(tok, "used") == 0) bit = 512;
        else goto done;
        if (seen & bit) {
            ret = "a field twice";
            goto done;
        }
        seen |= bit;
    }
    want = net ? 31u : 1023u;
    if (seen != want) goto done;
    if (net) {
        if (m->have_net) {
            ret = "a second network line";
            goto done;
        }
        m->have_net = 1;
    } else {
        if (m->n >= IMPORT_SUBS) {
            ret = "more than 64 subscribers";
            goto done;
        }
        m->sub[m->n++] = s;
    }
    ret = NULL;
done:
    oc_sig_wipe(&s, sizeof(s));
    return ret;
}

/* The file into m: 0, or 1 with the reason in o. */
static int load(imp_t *m, const char *path, oc_buf_t *o)
{
    char line[IMPORT_LINE];
    struct stat sb;
    size_t n = 0, pos = 0;
    unsigned ln = 0;
    int ret = 0;
    /* O_NONBLOCK: a FIFO with no writer must not hang the open (it is refused below) */
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) {
        oc_buf_printf(o, "%s: %s (nothing imported)\n", path, strerror(errno));
        return 1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        close(fd);
        oc_buf_printf(o, "%s: not a regular file (nothing imported)\n", path);
        return 1;
    }
    char *buf = sb.st_size <= (off_t)IMPORT_MAX ? malloc(IMPORT_MAX + 1u) : NULL;
    if (buf == NULL) {
        close(fd);
        oc_buf_printf(o, "%s: %s (nothing imported)\n", path,
                      sb.st_size > (off_t)IMPORT_MAX ? "larger than 64 KiB: not an ocbench HSS" : "out of memory");
        return 1;
    }
    for (;;) { /* one byte past the cap, to see a file that grew */
        ssize_t r = read(fd, buf + n, IMPORT_MAX + 1u - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) ret = 1;
        if (r <= 0) break;
        n += (size_t)r;
        if (n > IMPORT_MAX) break;
    }
    close(fd);
    if (ret != 0) oc_buf_printf(o, "%s: read error (nothing imported)\n", path);
    if (ret == 0 && n > IMPORT_MAX) {
        oc_buf_printf(o, "%s: larger than 64 KiB: not an ocbench HSS (nothing imported)\n", path);
        ret = 1;
    }
    while (ret == 0 && pos < n) {
        const char *start = buf + pos, *nl = memchr(start, '\n', n - pos);
        size_t len = nl != NULL ? (size_t)(nl - start) : n - pos;
        const char *why = NULL;
        pos += len + (nl != NULL);
        ln++;
        if (memchr(start, '\0', len) != NULL) why = "a NUL byte in the line";
        else {
            if (len > 0 && start[len - 1u] == '\r') len--; /* CRLF, as an editor may leave it */
            if (len >= sizeof(line)) why = "line too long for an ocbench HSS line";
        }
        if (why == NULL) {
            char *save = NULL, *kind;
            memcpy(line, start, len);
            line[len] = '\0';
            kind = strtok_r(line, " \t", &save);
            if (kind == NULL || kind[0] == '#') continue;
            why = parse_line(m, kind, save);
        }
        if (why != NULL) {
            oc_buf_printf(o, "%s:%u: %s (nothing imported)\n", path, ln, why);
            ret = 1;
        }
    }
    oc_sig_wipe(line, sizeof(line));
    oc_sig_wipe(buf, IMPORT_MAX + 1u);
    free(buf);
    return ret;
}

/* Everything, before anything is written: 0, or 1 with the reason in o.
 * *key_there: the network key is in the database already (the same one). */
static int check(oc_admin_t *a, imp_t *m, const char *path, int *key_there, oc_buf_t *o)
{
    oc_core_store_t st = oc_sql_store(a->sql);
    oc_core_netkey_t have;
    uint8_t pk[32];
    int bad = !m->have_net || oc_sig_x25519_public(m->sk, pk) != 0 || memcmp(pk, m->pk, 32) != 0;
    oc_sig_wipe(pk, sizeof(pk));
    if (bad) {
        oc_buf_printf(o, "%s: no network line, or its key pair does not match (nothing imported)\n", path);
        return 1;
    }
    if (m->key_id != a->cfg->key_id) {
        oc_buf_printf(o, "%s: network key %u, but key_id = %u in oc-core.conf (nothing imported)\n", path, m->key_id,
                      a->cfg->key_id);
        return 1;
    }
    int got = st.netkey_get(st.ctx, m->key_id, &have);
    int same = got == 0 && memcmp(have.pk, m->pk, 32) == 0;
    oc_sig_wipe(&have, sizeof(have));
    if (got == OC_CORE_STORE_FAILED || (got != 0 && got != OC_CORE_STORE_NONE)) {
        oc_buf_printf(o, "store error: network key %u can't be read (nothing imported)\n", m->key_id);
        return 1;
    }
    if (got == 0 && !same) {
        oc_buf_printf(o, "a different network key %u is in the database already (nothing imported)\n", m->key_id);
        return 1;
    }
    *key_there = got == 0;
    for (unsigned i = 0; i < m->n; i++) {
        oc_core_sub_t x;
        char t[OC_SIG_NUMBER_TEXT];
        const uint8_t *n = m->sub[i].number;
        oc_sig_number_to_text(n, t);
        if (!oc_sig_number_valid(n) || oc_core_number_reserved(n) ||
            !oc_core_route_home(a->route, oc_core_route_find(a->route, n))) {
            oc_buf_printf(o, "%s: not a number of a block this core is home for, or reserved (nothing imported)\n", t);
            return 1;
        }
        for (unsigned j = 0; j < i; j++) {
            if (memcmp(m->sub[j].number, n, OC_SIG_NUMBER_LEN) == 0 ||
                (m->sub[i].activated && m->sub[j].activated && m->sub[j].tmid == m->sub[i].tmid)) {
                oc_buf_printf(o, "%s: twice in the file, or its terminal is (nothing imported)\n", t);
                return 1;
            }
        }
        got = st.sub_get(st.ctx, n, &x);
        oc_sig_wipe(&x, sizeof(x));
        if (got == 0) {
            oc_buf_printf(o, "%s: already a subscriber (nothing imported)\n", t);
            return 1;
        }
        if (got != OC_CORE_STORE_NONE) {
            oc_buf_printf(o, "store error: %s can't be read (nothing imported)\n", t);
            return 1;
        }
        if (!m->sub[i].activated) continue;
        got = m->sub[i].tmid != 0 ? st.sub_by_tmid(st.ctx, m->sub[i].tmid, &x) : 0;
        oc_sig_wipe(&x, sizeof(x));
        if (got == 0) {
            oc_buf_printf(o, "%s: terminal %08x is bound already, or none (nothing imported)\n", t, m->sub[i].tmid);
            return 1;
        }
        if (got != OC_CORE_STORE_NONE) {
            oc_buf_printf(o, "store error: terminal %08x can't be looked up (nothing imported)\n", m->sub[i].tmid);
            return 1;
        }
    }
    return 0;
}

/* The writes, inside the caller's transaction: 0, or 1 (then the commit
 * fails too: a failed write dooms the transaction, oc_core_store.h). */
static int write_all(oc_admin_t *a, const imp_t *m, int key_there)
{
    oc_core_store_t st = oc_sql_store(a->sql);
    uint32_t now = (uint32_t)time(NULL);
    int bad = 0;
    if (!key_there) {
        oc_core_netkey_t key;
        memset(&key, 0, sizeof(key));
        key.key_id = m->key_id;
        memcpy(key.sk, m->sk, 32);
        memcpy(key.pk, m->pk, 32);
        key.period_s = m->period;
        key.created = now;
        bad |= st.netkey_put(st.ctx, &key) != 0;
        oc_sig_wipe(&key, sizeof(key));
    }
    for (unsigned i = 0; i < m->n; i++) {
        oc_core_sub_t x;
        memset(&x, 0, sizeof(x));
        memcpy(x.number, m->sub[i].number, OC_SIG_NUMBER_LEN);
        x.state = OC_CORE_SUB_ACTIVE;
        if (m->sub[i].activated) {
            x.activated = 1;
            x.tmid = m->sub[i].tmid;
            memcpy(x.k, m->sub[i].k, 16);
            memcpy(x.opc, m->sub[i].opc, 16);
            x.sqn = oc_sig_sqn_get(m->sub[i].sqn);
        }
        x.created = x.updated = now;
        bad |= st.sub_put(st.ctx, &x) != 0;
        oc_sig_wipe(&x, sizeof(x));
    }
    return bad;
}

int oc_import_ocb_hss(oc_admin_t *a, const char *path, oc_buf_t *o)
{
    int key_there = 0;
    if (a->core != NULL) {
        oc_buf_printf(o, "import-ocb-hss runs only with --offline, on a stopped core\n");
        return 1;
    }
    imp_t *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        oc_buf_printf(o, "out of memory (nothing imported)\n");
        return 1;
    }
    int rc = load(m, path, o);
    if (rc == 0) {
        oc_core_store_t st = oc_sql_store(a->sql);
        if (st.begin(st.ctx) != 0) { /* the write lock, before the checks */
            st.commit(st.ctx);       /* closes the doomed transaction (-1 by contract) */
            oc_buf_printf(o, "store error: can't take the database's write lock (nothing imported)\n");
            rc = 1;
        } else {
            rc = check(a, m, path, &key_there, o);
            int wrote = rc == 0 && write_all(a, m, key_there) == 0;
            /* refused: an empty transaction ends it and writes nothing */
            if (st.commit(st.ctx) != 0 && rc == 0) wrote = 0;
            if (rc == 0 && !wrote) {
                oc_buf_printf(o, "store error: nothing imported\n");
                rc = 1;
            }
        }
    }
    if (rc == 0) {
        oc_buf_printf(o, "network key %u %s\n", m->key_id, key_there ? "was there already" : "imported");
        for (unsigned i = 0; i < m->n; i++) {
            char t[OC_SIG_NUMBER_TEXT];
            oc_sig_number_to_text(m->sub[i].number, t);
            if (m->sub[i].activated) {
                oc_buf_printf(o, "%s  terminal %08x  sqn %llu  imported\n", t, m->sub[i].tmid,
                              (unsigned long long)oc_sig_sqn_get(m->sub[i].sqn));
            } else {
                oc_buf_printf(o, "%s  not activated: give it a code with `oc-core admin sub issue %s`\n", t, t);
            }
        }
    }
    oc_sig_wipe(m, sizeof(*m));
    free(m);
    return rc;
}
