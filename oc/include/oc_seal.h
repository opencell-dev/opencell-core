/* Keys at rest (network-core spec §5): K, OPc, the network SKn and token
 * secrets are sealed with AES-256-GCM under a 32-byte master key that is not
 * in the database. A sealed blob is
 *   version (1) | nonce (12, random) | ciphertext | tag (16)
 * and its AAD is table | 0 | column | 0 | primary key | version, so a blob
 * copied to another row, column or table does not open. version is the
 * master key's version (OC_SEAL_VERSION): a later key rotation re-seals
 * under a new one. */
#ifndef OC_SEAL_H
#define OC_SEAL_H

#include <stddef.h>
#include <stdint.h>

#define OC_SEAL_VERSION  1u
#define OC_SEAL_OVERHEAD 29u /* version + nonce + tag */
#define OC_SEAL_PT_MAX   64u /* the largest secret sealed here (SKn is 32) */

/* out gets n + OC_SEAL_OVERHEAD bytes. 0, or -1 (n > OC_SEAL_PT_MAX, crypto
 * failure). */
int oc_seal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
            const uint8_t *pt, size_t n, const uint8_t nonce[12], uint8_t *out);
/* pt gets in_n - OC_SEAL_OVERHEAD bytes. 0, or -1: a wrong key, a blob from
 * another row/column/table, a changed byte, an unknown version, or a
 * length that is not n + OC_SEAL_OVERHEAD for some n <= OC_SEAL_PT_MAX. */
int oc_unseal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
              const uint8_t *in, size_t in_n, uint8_t *pt);
/* The master key from path: a regular file of exactly 32 bytes that neither
 * group nor others may read (a systemd credential, or --key-file on the
 * bench). 0, or -1 with the reason in err. */
int oc_key_load(const char *path, uint8_t key[32], char *err, size_t cap);

#endif
