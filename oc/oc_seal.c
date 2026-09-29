#define _GNU_SOURCE
#include "oc_seal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "oc_sig_keys.h" /* oc_sig_wipe: a memset the compiler may not drop */

#define AAD_MAX 128u

static size_t aad(uint8_t out[AAD_MAX], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
                  uint8_t version)
{
    size_t t = strlen(table) + 1u, c = strlen(column) + 1u;
    /* Bound each part before summing: a huge pk_n (an attacker-influenced
     * primary key length) could otherwise wrap t + c + pk_n + 1 around
     * size_t back under AAD_MAX, passing a single combined check and
     * running memcpy(out + t + c, pk, pk_n) with pk_n bytes into an
     * AAD_MAX-byte stack buffer. */
    if (t >= AAD_MAX || c >= AAD_MAX || pk_n >= AAD_MAX) return 0;
    if (t + c + pk_n + 1u > AAD_MAX) return 0;
    memcpy(out, table, t);
    memcpy(out + t, column, c);
    memcpy(out + t + c, pk, pk_n);
    out[t + c + pk_n] = version;
    return t + c + pk_n + 1u;
}

/* One GCM pass: enc 1 seals (tag out), 0 opens (tag in, checked). */
static int gcm(int enc, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *a, size_t an,
               const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16])
{
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int len = 0, ok = x != NULL;
    ok = ok && EVP_CipherInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1;
    ok = ok && EVP_CipherInit_ex(x, NULL, NULL, key, nonce, enc) == 1;
    ok = ok && EVP_CipherUpdate(x, NULL, &len, a, (int)an) == 1;
    ok = ok && EVP_CipherUpdate(x, out, &len, in, (int)n) == 1;
    if (!enc) ok = ok && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
    ok = ok && EVP_CipherFinal_ex(x, out + len, &len) == 1;
    if (enc) ok = ok && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(x);
    return ok ? 0 : -1;
}

int oc_seal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
            const uint8_t *pt, size_t n, const uint8_t nonce[12], uint8_t *out)
{
    uint8_t a[AAD_MAX];
    size_t an = aad(a, table, column, pk, pk_n, OC_SEAL_VERSION);
    if (an == 0 || n > OC_SEAL_PT_MAX) return -1;
    out[0] = OC_SEAL_VERSION;
    memcpy(out + 1, nonce, 12);
    return gcm(1, key, nonce, a, an, pt, n, out + 13, out + 13 + n);
}

int oc_unseal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
              const uint8_t *in, size_t in_n, uint8_t *pt)
{
    uint8_t a[AAD_MAX], tag[16], buf[OC_SEAL_PT_MAX];
    if (in_n < OC_SEAL_OVERHEAD || in_n - OC_SEAL_OVERHEAD > OC_SEAL_PT_MAX || in[0] != OC_SEAL_VERSION) return -1;
    size_t n = in_n - OC_SEAL_OVERHEAD;
    size_t an = aad(a, table, column, pk, pk_n, in[0]);
    if (an == 0) return -1;
    memcpy(tag, in + 13 + n, 16);
    if (gcm(0, key, in + 1, a, an, in + 13, n, buf, tag) != 0) {
        oc_sig_wipe(buf, sizeof(buf));
        return -1; /* nothing of a blob that failed its tag reaches the caller */
    }
    memcpy(pt, buf, n);
    oc_sig_wipe(buf, sizeof(buf));
    return 0;
}

int oc_seal_owner_ok(uid_t file_uid, uid_t self)
{
    return file_uid == self || file_uid == 0;
}

/* Read up to cap bytes, looping past short reads and EINTR, stopping at
 * EOF. -1 only on a real read() error (errno left set). The caller compares
 * the return value against the exact size it wants, rather than trusting a
 * separate fstat()'d size that a concurrent writer could have moved past by
 * the time read() actually runs. */
static ssize_t read_full(int fd, uint8_t *buf, size_t cap)
{
    size_t got = 0;
    while (got < cap) {
        ssize_t r = read(fd, buf + got, cap - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break; /* EOF */
        got += (size_t)r;
    }
    return (ssize_t)got;
}

int oc_key_load(const char *path, uint8_t key[32], char *err, size_t cap)
{
    struct stat st;
    uint8_t buf[33]; /* one more than a valid key: any file with >= 33 bytes reads full and is refused */
    /* O_NONBLOCK: a FIFO with no writer (or certain devices) would
     * otherwise hang this open() forever; the regular-file check below
     * rejects it once opened, and O_NONBLOCK has no effect on a real
     * regular file's read(). O_NOCTTY: never let a tty path become this
     * process's controlling terminal. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0) {
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(err, cap, "%s: not a regular file", path);
        close(fd);
        return -1;
    }
    if ((st.st_mode & 077) != 0) {
        snprintf(err, cap, "%s: accessible by group or others (mode %03o): chmod 0400 it", path,
                 (unsigned)(st.st_mode & 0777));
        close(fd);
        return -1;
    }
    if (!oc_seal_owner_ok(st.st_uid, geteuid())) {
        snprintf(err, cap, "%s: owned by uid %u, not this user or root", path, (unsigned)st.st_uid);
        close(fd);
        return -1;
    }
    ssize_t r = read_full(fd, buf, sizeof(buf));
    close(fd);
    if (r < 0) {
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        oc_sig_wipe(buf, sizeof(buf));
        return -1;
    }
    if (r != 32) {
        /* Covers both a too-short file and, by reading one byte past 32,
         * a file that has grown to 33+ bytes since fstat() reported its
         * size (or was always larger): the size that matters is what
         * read() actually delivers, not a stat() snapshot that a
         * concurrent writer could have raced past. */
        snprintf(err, cap, "%s: the master key must be exactly 32 bytes", path);
        oc_sig_wipe(buf, sizeof(buf));
        return -1;
    }
    memcpy(key, buf, 32);
    oc_sig_wipe(buf, sizeof(buf));
    return 0;
}
