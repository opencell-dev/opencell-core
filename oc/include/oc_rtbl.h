/* The signed routing table (OCSS spec 2026-11-01 §3): the root table the
 * offline routing authority signs (OCRT), the additions a delegate key
 * signs (OCRA), their byte formats, Ed25519 (OpenSSL), the acceptance
 * rules of §3.5, and the effective table a core routes by (an
 * oc_core_route_t). No I/O but what a caller hands in: the daemon reads
 * the file and the database rows, the laptop tool oc-route writes them.
 *
 * Every integer is little-endian; text is len (1) | bytes. */
#ifndef OC_RTBL_H
#define OC_RTBL_H

#include <stddef.h>
#include <stdint.h>

#include "oc_core_route.h"

#define OC_RTBL_SIG       64u
#define OC_RTBL_KEY       32u
#define OC_RTBL_CORES     16u
#define OC_RTBL_DELEGS    4u
#define OC_RTBL_REVOKED   16u
#define OC_RTBL_STATES    80u
#define OC_RTBL_ADD_MAX   16u   /* blocks in one addition */
#define OC_RTBL_BLOB_MAX  400u  /* an addition's blob (it travels in one admin frame) */
#define OC_RTBL_ROOT_MAX  65536u
#define OC_RTBL_SEQ_MAX   1024u /* additions on one root version a core keeps track of */
#define OC_RTBL_SCOPE_ADD_NPA 1u

typedef struct {
    uint16_t id;
    char     name[32];
} oc_rtbl_core_t;

typedef struct {
    char     prefix[OC_SIG_NUMBER_DIGITS + 1];
    uint16_t idx, tenant, home;
    uint8_t  nsec;
    uint16_t sec[2];
    uint16_t epoch;
    char     state[OC_CORE_STATE_MAX + 1];
} oc_rtbl_block_t;

typedef struct {
    uint8_t  pub[OC_RTBL_KEY];
    uint8_t  scope;
    uint32_t not_before, not_after;
    uint16_t tenant, east, west;
    uint8_t  neast, nwest;
    char     east_st[OC_RTBL_STATES][OC_CORE_STATE_MAX + 1];
    char     west_st[OC_RTBL_STATES][OC_CORE_STATE_MAX + 1];
} oc_rtbl_deleg_t;

typedef struct {
    uint32_t        version, issued;
    uint16_t        max_idx;
    uint8_t         ncores;
    oc_rtbl_core_t  cores[OC_RTBL_CORES];
    uint16_t        nblocks;
    oc_rtbl_block_t blocks[OC_CORE_BLOCKS];
    uint8_t         ndeleg;
    oc_rtbl_deleg_t deleg[OC_RTBL_DELEGS];
    uint8_t         nrevoked;
    uint8_t         revoked[OC_RTBL_REVOKED][OC_RTBL_KEY];
} oc_rtbl_root_t;

typedef struct {
    char     npa[4];
    uint16_t idx;
    char     state[OC_CORE_STATE_MAX + 1];
} oc_rtbl_addblk_t;

typedef struct {
    uint32_t         root_version;
    uint16_t         seq;
    uint32_t         issued;
    uint8_t          delegate[OC_RTBL_KEY];
    uint8_t          n;
    oc_rtbl_addblk_t b[OC_RTBL_ADD_MAX];
} oc_rtbl_add_t;

/* A core's effective table (§3.1): its root table, the additions applied
 * on it (seq of the last; each one's SHA-256, for the idempotent re-offer
 * of rule 6), and the route oc_core uses. */
typedef struct {
    uint16_t        self;
    oc_rtbl_root_t  root;
    uint8_t         root_blob_sha[32];
    uint16_t        seq;
    uint8_t         add_sha[OC_RTBL_SEQ_MAX][32]; /* [s - 1]: addition s */
    uint16_t        max_idx; /* the highest index in use or ever assigned */
    oc_core_route_t route;
} oc_rtbl_t;

/* The East and West lists of portal spec §4.3 (OCSS spec §3.3), what
 * oc-route writes into a delegation. NULL-terminated. */
extern const char *const OC_RTBL_EAST[];
extern const char *const OC_RTBL_WEST[];

/* 1 if s is a state code: "XX", "US-XX" or "CA-XX", capitals (§3.3). */
int    oc_rtbl_state_ok(const char *s);

/* Codecs (§3.2). decode: 0, or -1 with the reason in err (malformed);
 * encode: the length, or 0 (out too small or a field out of range). A
 * root's semantic rules (unique prefixes and indexes, homes in the
 * directory, indexes <= max_idx) are checked by decode too. */
int    oc_rtbl_root_decode(const uint8_t *blob, size_t n, oc_rtbl_root_t *t, char *err, size_t cap);
size_t oc_rtbl_root_encode(const oc_rtbl_root_t *t, uint8_t *out, size_t cap);
int    oc_rtbl_add_decode(const uint8_t *blob, size_t n, oc_rtbl_add_t *a, char *err, size_t cap);
size_t oc_rtbl_add_encode(const oc_rtbl_add_t *a, uint8_t *out, size_t cap);

/* Ed25519 (RFC 8032, pure): 1 if sig is pub's signature of msg. */
int    oc_rtbl_verify(const uint8_t pub[OC_RTBL_KEY], const uint8_t *msg, size_t n, const uint8_t sig[OC_RTBL_SIG]);
/* Signing, for the tool and the tests: from a raw 32-byte seed, or from a
 * PKCS#8 PEM file. 0 or -1. pub (if not NULL) gets the public key. */
int    oc_rtbl_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t n, uint8_t sig[OC_RTBL_SIG],
                         uint8_t pub[OC_RTBL_KEY]);
int    oc_rtbl_sign_pem(const char *path, const uint8_t *msg, size_t n, uint8_t sig[OC_RTBL_SIG],
                        uint8_t pub[OC_RTBL_KEY]);

/* A root table file (blob | sig) verified with root_pub and made the
 * effective table of core self (no additions yet). 0, or -1 with err:
 * malformed, bad signature, self not in the directory, or a block
 * oc_core_route_add refuses. */
int    oc_rtbl_load(oc_rtbl_t *t, uint16_t self, const uint8_t root_pub[OC_RTBL_KEY], const uint8_t *file, size_t n,
                    char *err, size_t cap);
/* The root version in a root table file, without verifying it (0: not one). */
uint32_t oc_rtbl_file_version(const uint8_t *file, size_t n);

/* §3.5's rules 2-8 for an addition offered to cur (rule 1, a signed table,
 * is the caller's): OC_RTBL_OK with next = cur plus the addition (*fresh
 * 1), or OC_RTBL_OK with next = cur and *fresh 0 (the same addition again,
 * rule 6), or the refusal with its message in msg. now is the wall clock
 * (unix s). next may not be cur. */
enum { OC_RTBL_OK = 0, OC_RTBL_INVALID = 1, OC_RTBL_TAKEN = 2, OC_RTBL_FULL = 3 };
int    oc_rtbl_offer(const oc_rtbl_t *cur, oc_rtbl_t *next, uint32_t table_version, const uint8_t *blob, size_t n,
                     const uint8_t sig[OC_RTBL_SIG], uint32_t now, int *fresh, char *msg, size_t cap);
/* The latest not_after of a delegation valid now (0: none). */
uint32_t oc_rtbl_deleg_until(const oc_rtbl_t *t, uint32_t now);

/* Hex: 2n digits of b into out (2n + 1 bytes); parse: 0 or -1. */
void   oc_rtbl_hex(const uint8_t *b, size_t n, char *out);
int    oc_rtbl_unhex(const char *s, uint8_t *out, size_t n);

#endif
