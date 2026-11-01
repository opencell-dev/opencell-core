/* oc-route: the routing authority's laptop tool (OCSS spec 2026-11-01
 * §3.7). It makes Ed25519 keys, the signed root table (one block per
 * geographic NPA, homed East/West by state, with the delegation for the
 * portal's key), and delegate additions, and shows either.
 *
 *   oc-route keygen KEY
 *   oc-route pub KEY
 *   oc-route make ROOT_KEY OUT --version N --npa CSV --core ID=NAME... --east ID --west ID
 *                 [--prev OLD.tbl] [--pin NPA=IDX]... [--delegate PUBHEX [--valid-days D]]...
 *                 [--revoke PUBHEX]... [--now UNIX]
 *   oc-route add DELEGATE_KEY BASE.tbl OUT --seq N --npa NPA,STATE[,IDX]... [--now UNIX]
 *   oc-route show FILE [--root PUBHEX]
 *
 * Keys are PKCS#8 PEM files, written 0600 and never overwritten. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "oc_rtbl.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: oc-route keygen KEY | pub KEY\n"
            "       oc-route make ROOT_KEY OUT --version N --npa CSV --core ID=NAME... --east ID --west ID\n"
            "                     [--prev OLD.tbl] [--pin NPA=IDX]... [--delegate PUBHEX [--valid-days D]]...\n"
            "                     [--revoke PUBHEX]... [--now UNIX]\n"
            "       oc-route add DELEGATE_KEY BASE.tbl OUT --seq N --npa NPA,STATE[,IDX]... [--now UNIX]\n"
            "       oc-route show FILE [--root PUBHEX]\n");
    return 2;
}

static int die(const char *what)
{
    fprintf(stderr, "oc-route: %s\n", what);
    return 1;
}

static long num(const char *s, long lo, long hi)
{
    char *e;
    errno = 0;
    long v = strtol(s, &e, 10);
    return errno != 0 || *s == '\0' || *e != '\0' || v < lo || v > hi ? -1 : v;
}

static uint8_t *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    uint8_t *b = malloc(OC_RTBL_ROOT_MAX + 1u);
    *n = b != NULL ? fread(b, 1, OC_RTBL_ROOT_MAX + 1u, f) : 0;
    fclose(f);
    if (b != NULL && *n > OC_RTBL_ROOT_MAX) {
        free(b);
        return NULL;
    }
    return b;
}

/* blob | sig to path, created anew (a table is never overwritten). */
static int write_signed(const char *path, const uint8_t *blob, size_t n, const uint8_t sig[64])
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) return -1;
    int ok = write(fd, blob, n) == (ssize_t)n && write(fd, sig, 64) == 64;
    return close(fd) == 0 && ok ? 0 : -1;
}

static int pem_pub(const char *path, uint8_t pub[32])
{
    uint8_t sig[64];
    return oc_rtbl_sign_pem(path, (const uint8_t *)"", 0, sig, pub);
}

static void print_hex(const uint8_t *b, size_t n)
{
    char h[2 * 64 + 1];
    oc_rtbl_hex(b, n, h);
    printf("%s\n", h);
}

static int cmd_keygen(int argc, char **argv)
{
    if (argc != 3) return usage();
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (k == NULL) return die("key generation failed");
    int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        EVP_PKEY_free(k);
        return die("can't create the key file (it must not exist)");
    }
    FILE *f = fdopen(fd, "w");
    int ok = f != NULL && PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL) == 1;
    if (f != NULL && fclose(f) != 0) ok = 0;
    uint8_t pub[32];
    size_t pl = sizeof(pub);
    ok = ok && EVP_PKEY_get_raw_public_key(k, pub, &pl) == 1;
    EVP_PKEY_free(k);
    if (!ok) return die("writing the key failed");
    print_hex(pub, 32);
    return 0;
}

static int cmd_pub(int argc, char **argv)
{
    uint8_t pub[32];
    if (argc != 3) return usage();
    if (pem_pub(argv[2], pub) != 0) return die("not an Ed25519 PKCS#8 PEM key");
    print_hex(pub, 32);
    return 0;
}

static int in_list(const char *const *l, const char *s)
{
    for (; *l != NULL; l++) {
        if (strcmp(*l, s) == 0) return 1;
    }
    return 0;
}

static oc_rtbl_root_t T, PREV;

static int cmd_make(int argc, char **argv)
{
    if (argc < 4) return usage();
    const char *key = argv[2], *out = argv[3], *csv = NULL, *prev = NULL;
    long version = -1, east = -1, west = -1, days = 365, now = (long)time(NULL);
    uint8_t deleg[OC_RTBL_DELEGS][32];
    unsigned ndeleg = 0;
    struct { unsigned npa; long idx; } pins[64];
    unsigned npin = 0;
    memset(&T, 0, sizeof(T));
    for (int i = 4; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) return usage();
        i++;
        if (strcmp(a, "--version") == 0) {
            version = num(v, 1, 0xFFFFFFFFl);
        } else if (strcmp(a, "--npa") == 0) {
            csv = v;
        } else if (strcmp(a, "--prev") == 0) {
            prev = v;
        } else if (strcmp(a, "--east") == 0) {
            east = num(v, 1, 65535);
        } else if (strcmp(a, "--west") == 0) {
            west = num(v, 1, 65535);
        } else if (strcmp(a, "--valid-days") == 0) {
            days = num(v, 1, 3650);
        } else if (strcmp(a, "--now") == 0) {
            now = num(v, 1, 0xFFFFFFFFl);
        } else if (strcmp(a, "--core") == 0) {
            const char *eq = strchr(v, '=');
            char idt[8];
            if (eq == NULL || eq - v >= (long)sizeof(idt) || T.ncores >= OC_RTBL_CORES || strlen(eq + 1) == 0 ||
                strlen(eq + 1) > 31) {
                return die("--core ID=NAME");
            }
            memcpy(idt, v, (size_t)(eq - v));
            idt[eq - v] = '\0';
            long id = num(idt, 1, 65535);
            if (id < 0) return die("--core ID=NAME");
            T.cores[T.ncores].id = (uint16_t)id;
            snprintf(T.cores[T.ncores].name, sizeof(T.cores[0].name), "%s", eq + 1);
            T.ncores++;
        } else if (strcmp(a, "--pin") == 0) {
            unsigned npa;
            long idx;
            if (npin >= 64 || sscanf(v, "%3u=%ld", &npa, &idx) != 2 || idx < 1 || idx > 65535) return die("--pin NPA=IDX");
            pins[npin].npa = npa;
            pins[npin++].idx = idx;
        } else if (strcmp(a, "--delegate") == 0) {
            if (ndeleg >= OC_RTBL_DELEGS || oc_rtbl_unhex(v, deleg[ndeleg], 32) != 0) return die("--delegate PUBHEX");
            ndeleg++;
        } else if (strcmp(a, "--revoke") == 0) {
            if (T.nrevoked >= OC_RTBL_REVOKED || oc_rtbl_unhex(v, T.revoked[T.nrevoked], 32) != 0) {
                return die("--revoke PUBHEX");
            }
            T.nrevoked++;
        } else {
            return usage();
        }
    }
    if (version < 0 || east < 0 || west < 0 || east == west || days < 0 || now < 0 || csv == NULL || T.ncores == 0) {
        return die("--version, --npa, --core, --east and --west are needed (east and west differ)");
    }
    T.version = (uint32_t)version;
    T.issued = (uint32_t)now;
    char err[160];
    if (prev != NULL) {
        size_t n;
        uint8_t *b = slurp(prev, &n);
        if (b == NULL || n <= 64 || oc_rtbl_root_decode(b, n - 64, &PREV, err, sizeof(err)) != 0) {
            free(b);
            return die("--prev: not a root table");
        }
        free(b);
        if (PREV.version >= T.version) return die("--version must be above the previous table's");
    }
    uint16_t hw = prev != NULL ? PREV.max_idx : 0;
    for (unsigned i = 0; i < npin; i++) {
        if (pins[i].idx > hw) hw = (uint16_t)pins[i].idx;
    }
    FILE *f = fopen(csv, "r");
    if (f == NULL) return die("--npa: can't read the CSV");
    char line[128];
    unsigned lineno = 0;
    int bad = 0;
    struct { unsigned npa; char state[OC_CORE_STATE_MAX + 1]; } rows[OC_CORE_BLOCKS];
    unsigned nrows = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;
        unsigned npa;
        char st[OC_CORE_STATE_MAX + 1];
        if (sscanf(line, "%3u,%5s", &npa, st) != 2 || !oc_rtbl_state_ok(st) || nrows >= OC_CORE_BLOCKS) {
            fprintf(stderr, "oc-route: %s:%u: NPA,STATE expected\n", csv, lineno);
            bad = 1;
            continue;
        }
        rows[nrows].npa = npa;
        snprintf(rows[nrows].state, sizeof(rows[0].state), "%s", st);
        nrows++;
    }
    fclose(f);
    if (bad) return 1;
    /* NPA order */
    for (unsigned i = 1; i < nrows; i++) {
        for (unsigned j = i; j > 0 && rows[j - 1].npa > rows[j].npa; j--) {
            __typeof__(rows[0]) x = rows[j];
            rows[j] = rows[j - 1];
            rows[j - 1] = x;
        }
    }
    for (unsigned i = 0; i < nrows; i++) {
        oc_rtbl_block_t *b = &T.blocks[T.nblocks];
        memset(b, 0, sizeof(*b));
        snprintf(b->prefix, sizeof(b->prefix), "8831%03u", rows[i].npa);
        if (!oc_core_route_prefix_ok(b->prefix)) {
            fprintf(stderr, "oc-route: NPA %03u is not a legal NPA\n", rows[i].npa);
            return 1;
        }
        int is_east = in_list(OC_RTBL_EAST, rows[i].state), is_west = in_list(OC_RTBL_WEST, rows[i].state);
        if (!is_east && !is_west) {
            fprintf(stderr, "oc-route: NPA %03u: state %s is in neither list\n", rows[i].npa, rows[i].state);
            return 1;
        }
        b->home = (uint16_t)(is_east ? east : west);
        b->nsec = 1;
        b->sec[0] = (uint16_t)(is_east ? west : east);
        b->tenant = 1;
        b->epoch = 1;
        snprintf(b->state, sizeof(b->state), "%s", rows[i].state);
        for (unsigned p = 0; prev != NULL && p < PREV.nblocks && b->idx == 0; p++) {
            if (strcmp(PREV.blocks[p].prefix, b->prefix) == 0) {
                b->idx = PREV.blocks[p].idx;
                b->epoch = PREV.blocks[p].epoch;
            }
        }
        for (unsigned p = 0; p < npin && b->idx == 0; p++) {
            if (pins[p].npa == rows[i].npa) b->idx = (uint16_t)pins[p].idx;
        }
        if (b->idx == 0) {
            if (hw == 65535) return die("no block index left");
            b->idx = ++hw;
        }
        T.nblocks++;
    }
    for (unsigned p = 0; prev != NULL && p < PREV.nblocks; p++) { /* never dropped silently */
        int found = 0;
        for (unsigned i = 0; i < T.nblocks; i++) found |= strcmp(T.blocks[i].prefix, PREV.blocks[p].prefix) == 0;
        if (!found) {
            if (T.nblocks >= OC_CORE_BLOCKS) return die("too many blocks");
            T.blocks[T.nblocks++] = PREV.blocks[p];
            fprintf(stderr, "oc-route: kept %s (index %u): in the previous table, not in the CSV\n",
                    PREV.blocks[p].prefix, PREV.blocks[p].idx);
        }
    }
    T.max_idx = hw;
    for (unsigned i = 0; i < ndeleg; i++) {
        oc_rtbl_deleg_t *d = &T.deleg[T.ndeleg++];
        memcpy(d->pub, deleg[i], 32);
        d->scope = OC_RTBL_SCOPE_ADD_NPA;
        d->not_before = (uint32_t)now;
        d->not_after = (uint32_t)now + (uint32_t)days * 86400u;
        d->tenant = 1;
        d->east = (uint16_t)east;
        d->west = (uint16_t)west;
        for (const char *const *s = OC_RTBL_EAST; *s != NULL; s++) snprintf(d->east_st[d->neast++], 6, "%s", *s);
        for (const char *const *s = OC_RTBL_WEST; *s != NULL; s++) snprintf(d->west_st[d->nwest++], 6, "%s", *s);
    }
    static uint8_t blob[OC_RTBL_ROOT_MAX];
    size_t n = oc_rtbl_root_encode(&T, blob, sizeof(blob));
    if (n == 0 || n + 64 > OC_RTBL_ROOT_MAX) return die("the table does not encode");
    if (oc_rtbl_root_decode(blob, n, &PREV, err, sizeof(err)) != 0) { /* what the cores will check */
        fprintf(stderr, "oc-route: the table would be refused: %s\n", err);
        return 1;
    }
    uint8_t sig[64], pub[32];
    if (oc_rtbl_sign_pem(key, blob, n, sig, pub) != 0) return die("can't sign with ROOT_KEY");
    if (write_signed(out, blob, n, sig) != 0) return die("can't write OUT (it must not exist)");
    char h[65];
    oc_rtbl_hex(pub, 32, h);
    printf("root table version %u: %u blocks, max index %u, %u delegation(s), %u revoked; %zu bytes; root key %s\n",
           (unsigned)T.version, (unsigned)T.nblocks, (unsigned)T.max_idx, (unsigned)T.ndeleg, (unsigned)T.nrevoked,
           n + 64u, h);
    return 0;
}

static int cmd_add(int argc, char **argv)
{
    if (argc < 5) return usage();
    const char *key = argv[2], *base = argv[3], *out = argv[4];
    oc_rtbl_add_t a;
    long seq = -1, now = (long)time(NULL);
    memset(&a, 0, sizeof(a));
    size_t n;
    char err[160];
    uint8_t *b = slurp(base, &n);
    if (b == NULL || n <= 64 || oc_rtbl_root_decode(b, n - 64, &T, err, sizeof(err)) != 0) {
        free(b);
        return die("BASE.tbl: not a root table");
    }
    free(b);
    uint16_t next = T.max_idx;
    for (int i = 5; i < argc; i++) {
        const char *o = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) return usage();
        i++;
        if (strcmp(o, "--seq") == 0) {
            seq = num(v, 1, 65535);
        } else if (strcmp(o, "--now") == 0) {
            now = num(v, 1, 0xFFFFFFFFl);
        } else if (strcmp(o, "--npa") == 0) {
            oc_rtbl_addblk_t *x = &a.b[a.n];
            char st[OC_CORE_STATE_MAX + 1];
            long idx = 0;
            int got = a.n < OC_RTBL_ADD_MAX ? sscanf(v, "%3[0-9],%5[A-Z-],%ld", x->npa, st, &idx) : 0;
            if (got < 2 || !oc_rtbl_state_ok(st)) return die("--npa NPA,STATE[,IDX]");
            snprintf(x->state, sizeof(x->state), "%s", st);
            x->idx = got == 3 ? (uint16_t)idx : ++next;
            if (x->idx > next) next = x->idx;
            a.n++;
        } else {
            return usage();
        }
    }
    if (seq < 0 || now < 0 || a.n == 0) return die("--seq and at least one --npa are needed");
    a.root_version = T.version;
    a.seq = (uint16_t)seq;
    a.issued = (uint32_t)now;
    uint8_t sig[64];
    if (pem_pub(key, a.delegate) != 0) return die("DELEGATE_KEY: not an Ed25519 PKCS#8 PEM key");
    uint8_t blob[OC_RTBL_BLOB_MAX];
    n = oc_rtbl_add_encode(&a, blob, sizeof(blob));
    if (n == 0) return die("the addition does not encode");
    if (oc_rtbl_sign_pem(key, blob, n, sig, NULL) != 0) return die("can't sign");
    if (write_signed(out, blob, n, sig) != 0) return die("can't write OUT (it must not exist)");
    char bh[2 * OC_RTBL_BLOB_MAX + 1], sh[129];
    oc_rtbl_hex(blob, n, bh);
    oc_rtbl_hex(sig, 64, sh);
    printf("addition %u.%u, %u block(s)\nblob %s\nsig  %s\n", (unsigned)a.root_version, (unsigned)a.seq,
           (unsigned)a.n, bh, sh);
    return 0;
}

static int cmd_show(int argc, char **argv)
{
    uint8_t root[32];
    int verify = 0;
    if (argc == 5 && strcmp(argv[3], "--root") == 0) {
        if (oc_rtbl_unhex(argv[4], root, 32) != 0) return die("--root PUBHEX");
        verify = 1;
    } else if (argc != 3) {
        return usage();
    }
    size_t n;
    uint8_t *b = slurp(argv[2], &n);
    char err[160], h[65];
    if (b == NULL || n <= 64) {
        free(b);
        return die("FILE: too short");
    }
    size_t bn = n - 64;
    int rc = 0;
    if (memcmp(b, "OCRT", 4) == 0) {
        if (oc_rtbl_root_decode(b, bn, &T, err, sizeof(err)) != 0) {
            fprintf(stderr, "oc-route: %s\n", err);
            free(b);
            return 1;
        }
        printf("root table version %u, issued %u, max index %u\n", (unsigned)T.version, (unsigned)T.issued,
               (unsigned)T.max_idx);
        for (unsigned i = 0; i < T.ncores; i++) printf("core %u %s\n", T.cores[i].id, T.cores[i].name);
        for (unsigned i = 0; i < T.nblocks; i++) {
            const oc_rtbl_block_t *x = &T.blocks[i];
            printf("block %s %u home %u secondary %u tenant %u epoch %u state %s\n", x->prefix, x->idx, x->home,
                   x->nsec ? x->sec[0] : 0, x->tenant, x->epoch, x->state[0] ? x->state : "-");
        }
        for (unsigned i = 0; i < T.ndeleg; i++) {
            oc_rtbl_hex(T.deleg[i].pub, 32, h);
            printf("delegate %s scope %u valid %u-%u east core %u (%u states) west core %u (%u states)\n", h,
                   T.deleg[i].scope, (unsigned)T.deleg[i].not_before, (unsigned)T.deleg[i].not_after,
                   T.deleg[i].east, T.deleg[i].neast, T.deleg[i].west, T.deleg[i].nwest);
        }
        for (unsigned i = 0; i < T.nrevoked; i++) {
            oc_rtbl_hex(T.revoked[i], 32, h);
            printf("revoked %s\n", h);
        }
    } else {
        oc_rtbl_add_t a;
        if (oc_rtbl_add_decode(b, bn, &a, err, sizeof(err)) != 0) {
            fprintf(stderr, "oc-route: %s\n", err);
            free(b);
            return 1;
        }
        oc_rtbl_hex(a.delegate, 32, h);
        printf("addition %u.%u issued %u by %s\n", (unsigned)a.root_version, (unsigned)a.seq, (unsigned)a.issued, h);
        for (unsigned i = 0; i < a.n; i++) printf("npa %s %u state %s\n", a.b[i].npa, a.b[i].idx, a.b[i].state);
        if (verify) memcpy(root, a.delegate, 32); /* an addition is checked against its own key */
    }
    if (verify) {
        int ok = oc_rtbl_verify(root, b, bn, b + bn);
        printf("signature %s\n", ok ? "ok" : "BAD");
        rc = ok ? 0 : 1;
    }
    free(b);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    if (strcmp(argv[1], "keygen") == 0) return cmd_keygen(argc, argv);
    if (strcmp(argv[1], "pub") == 0) return cmd_pub(argc, argv);
    if (strcmp(argv[1], "make") == 0) return cmd_make(argc, argv);
    if (strcmp(argv[1], "add") == 0) return cmd_add(argc, argv);
    if (strcmp(argv[1], "show") == 0) return cmd_show(argc, argv);
    return usage();
}
