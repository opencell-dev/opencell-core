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
#include <sys/types.h> /* uid_t, for oc_seal_owner_ok */

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
/* The master key from path: a regular file, exactly 32 bytes, owned by the
 * caller's effective user (or root) and unreadable by group or others (a
 * systemd credential, or --key-file on the bench). When the mode shows
 * group or other bits, the file must carry a POSIX access ACL
 * (system.posix_acl_access, version 2) in which the owning-group entry,
 * every named-group entry and the other entry grant nothing, every
 * named-user entry that grants anything names the caller's effective uid,
 * and there is no entry of another kind (the owner and mask entries may be
 * anything; the owner is checked as above). That is the credential systemd
 * makes on tmpfs for a service's user - root's, 0400, plus user:<uid>:r,
 * which stat() shows as 0440 (the mask) - and nothing that lets anyone else
 * read. Without such an ACL, group or other bits are refused. 0, or -1
 * with the reason in err. */
int oc_key_load(const char *path, uint8_t key[32], char *err, size_t cap);

/* Internal: true if a file owned by file_uid may be used by a process whose
 * effective uid is self (its own file, or root's). Exposed only so
 * oc_key_load's ownership check can be tested without a chown, which would
 * need root privileges the test process doesn't have. */
int oc_seal_owner_ok(uid_t file_uid, uid_t self);

#endif
