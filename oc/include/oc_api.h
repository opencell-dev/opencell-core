/* The core admin API (portal spec §7, network-core spec §18.1): the
 * operations the portal asks a core for, over mTLS (oc_apisrv.h carries
 * the bytes; this file is the protocol and the operations, with no I/O).
 *
 * Frames have §6's shape: len (2, BE) | type (1) | body, len counting type
 * and body, a frame at most OC_API_FRAME_MAX bytes; fields little-endian;
 * numbers 8 BCD bytes, full form; text is len (1) | UTF-8 bytes.
 *
 * A request's type is its operation (OC_API_*); its body is req (4) |
 * actor (4) | the operation's fields. The answer's type is 0x80 | the
 * operation's; its body is req (4) | status (1) | the result (OC_API_OK or
 * OC_API_MORE) or, for any other status, a message (text, for the
 * portal's log). A result too long for one frame comes as several answer
 * frames with the same req, each with status OC_API_MORE but the last
 * (OC_API_OK), each a whole list of its own rows (n (1) | n rows).
 *
 *   op                    request fields                 result
 *   0x01 num.free         exchange (text: 8831 NPA NXX)  n (1), n numbers
 *                         count (1: 1-32), pattern (text:
 *                         "" or 5 of [0-9x] over the last 5 digits)
 *   0x02 num.check        number                         0 free, 1 taken, 2 not assignable (1)
 *   0x03 sub.create       number                         number, expiry (4, unix s), QR text
 *   0x04 sub.reissue      number                         number, expiry (4, unix s), QR text
 *   0x05 sub.status       number                         number, activated (1), disabled (1),
 *                                                        token expiry (4, 0 none), registered (1),
 *                                                        cell (4, 0 none), the TMID's top 16 bits (2),
 *                                                        last seen (4, unix s, 0 never)
 *   0x06 sub.release      number                         -  (ok, too, when the number is free already:
 *                                                        released by the 72 h job, or never taken)
 *   0x07 sub.disable      number                         -
 *   0x08 sub.enable       number                         -
 *   0x09 cdr.list         number, since (4, unix s)      rows, newest first, at most OC_API_CDR_MAX:
 *                                                        setup, answer, end (4 each, unix s; answer 0:
 *                                                        not answered), cause (1, oc_sig), direction
 *                                                        (1: 0 the number called, 1 it was called),
 *                                                        the other number
 *   0x0A cell.add         name (text, 1-31), mode (1:     cell id (4)
 *                         1 part15, 2 part97), group (2)
 *   0x0B cell.set_cert    cell id (4), SHA-256 (32)      -
 *   0x0C cell.revoke      cell id (4)                    -  (disabled and unpinned)
 *   0x0D cell.status      cell id (4, 0: every cell)     rows: cell id (4), enabled (1), mode (1),
 *                                                        group (2), pinned (1), SHA-256 (32, zero if
 *                                                        not), linked (1), last HELLO (4, unix s),
 *                                                        terminals (2), calls (2), name (text)
 *   0x0E core.status      -                              core id (2), uptime (4, s), cells (4), cells
 *                                                        linked (4), activated subscribers (4), calls
 *                                                        (2), name (text), version (text)
 *   0x0F route.offer      (P5)                           always OC_API_UNSUPPORTED for now
 *
 * The core never answers with K, OPc, SQN or a token secret; the QR text
 * of a token it has just issued is the one secret it gives (spec §7).
 *
 * actor is the portal account the call is made for (0: the portal
 * itself). Every call is audited (event API, detail "a<actor> <op>
 * <status> [what]", the number in the record's number column, the cell in
 * its cell column), except calls a rate limit refused: the first in each
 * minute is audited, the rest counted into one record at the minute's end.
 * Every operation has its rate limit, route.offer too; op 0 and unknown
 * ops share one of their own, named "unknown" (api_rate = unknown ...). 
 *
 * An unactivated number whose token has expired is released before any
 * call about it (sub.release_expired, network-core spec §18.3), and every
 * minute for all of them (oc_api_tick). */
#ifndef OC_API_H
#define OC_API_H

#include <stddef.h>
#include <stdint.h>

#include "oc_admin.h" /* oc_buf_t */
#include "oc_core.h"
#include "oc_sql.h"

#define OC_API_FRAME_MAX 512u
#define OC_API_TOKEN_S   (72u * 3600u) /* a token the API issues: 72 h (portal spec §4.2) */
#define OC_API_CDR_MAX   1000u
#define OC_API_FREE_MAX  32u

enum {
    OC_API_NUM_FREE = 0x01, OC_API_NUM_CHECK, OC_API_SUB_CREATE, OC_API_SUB_REISSUE, OC_API_SUB_STATUS,
    OC_API_SUB_RELEASE, OC_API_SUB_DISABLE, OC_API_SUB_ENABLE, OC_API_CDR_LIST, OC_API_CELL_ADD,
    OC_API_CELL_SET_CERT, OC_API_CELL_REVOKE, OC_API_CELL_STATUS, OC_API_CORE_STATUS, OC_API_ROUTE_OFFER,
    OC_API_OPS /* one past the last */
};
#define OC_API_ANSWER 0x80u /* | op */

enum {
    OC_API_OK = 0, OC_API_MORE = 1,
    OC_API_INVALID = 0x10, OC_API_NOT_FOUND, OC_API_TAKEN, OC_API_NOT_ASSIGNABLE, OC_API_NOT_UNACTIVATED,
    OC_API_RATE_LIMITED, OC_API_UNAVAILABLE, OC_API_UNSUPPORTED
};

typedef struct {
    uint32_t per_hour, burst; /* a token bucket: burst calls at once, per_hour a sustained rate */
    uint64_t milli;           /* the bucket, in thousandths of a call */
    uint64_t at_us;           /* when it was last filled */
    uint32_t refused;         /* refusals in this minute not audited one by one */
    uint32_t refused_actor;   /* the last refused call's actor */
    uint64_t window_us;       /* the minute's end (0: none open) */
} oc_api_rate_t;

typedef struct {
    oc_sql_t              *sql;
    const oc_core_route_t *route;
    const oc_core_cfg_t   *cfg;
    oc_core_t             *core;
    uint64_t (*now_us)(void);   /* monotonic: rate limits, uptime, oc_core's clock */
    uint32_t (*unix_now)(void); /* wall clock: token expiry, registration times */
    const char *name, *version; /* core.status */
    uint64_t    started_us;
    oc_api_rate_t rate[OC_API_OPS];
    uint64_t    sweep_at_us; /* the next release of every expired number */
    /* private: the call being served, for its audit record */
    uint8_t  audit_number[OC_SIG_NUMBER_LEN];
    uint32_t audit_cell;
    char     audit_what[32];
} oc_api_t;

/* The rates default to OC_API's table (oc_api_rate_set changes them); the
 * caller sets the pointers and names first, then calls this. */
void oc_api_init(oc_api_t *a);
/* "OP PER_HOUR BURST" (the config's api_rate), e.g. "sub.disable 30 10":
 * 0, or -1 with err set. */
int  oc_api_rate_set(oc_api_t *a, const char *spec, char *err, size_t cap);
/* One whole request frame (len included, n = len + 2): the answer frames
 * are appended to out. 0, or -1: not a request at all (a bad length, a
 * body too short for req and actor, or an answer's type), so the caller
 * closes the connection; nothing is answered or audited then. */
int  oc_api_handle(oc_api_t *a, const uint8_t *frame, size_t n, oc_buf_t *out);
/* Every minute: every expired unactivated number released; the rate
 * limits' refusal counts audited. Call it from the loop. */
void oc_api_tick(oc_api_t *a);
/* number's (or, NULL, every) unactivated subscriber whose unused token
 * has expired is released, audited SUB_RELEASE "expired": how many, or -1
 * (the store failed). At most 256 in one call. */
int  oc_api_release_expired(oc_api_t *a, const uint8_t *number);
const char *oc_api_op_name(unsigned op); /* "sub.create", or "?" */
const char *oc_api_status_name(unsigned status); /* "ok", "taken", ... */

#endif
