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
 *   0x10 cell.radio       cell id (4, 0: every cell)     rows, per radio of a linked cell that has
 *                                                        reported (CELL_STATUS, NOC design §7.3): cell
 *                                                        id (4), radio (1), role (1), band (1), fw (3),
 *                                                        anchor (1), PPS (1), timebase (1), temp (1,
 *                                                        int8), board uptime (4, s), reported at (4,
 *                                                        unix s), schedules, rach, attach, grants, ACK
 *                                                        errors, ACK late (4 each), late slots, radio
 *                                                        errors (2 each), last radio error (2, int16),
 *                                                        schedule misses, UART CRC errors (2 each),
 *                                                        terminals heard (1)
 *   0x11 reg.list         cell id (4, 0: every cell),    rows, by number, at most OC_API_REG_MAX: number,
 *                         after (number; all zero: from  the TMID's top 16 bits (2), cell (4),
 *                         the start)                     registered at (4, unix s: the newest REGISTER
 *                                                        audit record, 0 none), expires (4), RSSI (2,
 *                                                        int16 dBm), SNR (2, int16 quarter dB; both
 *                                                        -32768: not reported), heard at (4, unix s, 0)
 *   0x12 cdr.recent       after (4, a CDR id; 0: from    rows, by id: id (4), setup, answer, end (4
 *                         the first), limit (2, 1-1000)  each, unix s), cause (1), caller, called,
 *                                                        cell a, cell b (4 each; 0: not a cell), leg
 *                                                        kinds (1: a << 4 | b; 0 cell, 1 echo, 2
 *                                                        playback, 3 peer)
 *   0x13 audit.list       after (4, an audit id), event  rows, by id: id (4), ts (4), event (1),
 *                         mask (4: bit e for event e;    number (zero: none), the TMID's top 16 bits
 *                         0: every event), number (zero: (2), cell (4), detail (text)
 *                         any), limit (2, 1-500)
 *   0x14 ocss.status      -                              rows, per configured OCSS peer: core id (2),
 *                                                        this core dials it (1), state (1: 0 down, 1
 *                                                        connecting, 2 handshake, 3 open, 4 up), since,
 *                                                        last rx, last tx (4 each, unix s; 0 never),
 *                                                        calls (1), frames dropped (4), address (text;
 *                                                        "-": it dials here)
 *   0x15 core.blocks      -                              rows: block index (2), home core (2), this
 *                                                        core's role (1: 0 none, 1 home, 2 secondary),
 *                                                        prefix (text, digits)
 *   0x16 cell.mode        cell id (4), mode (1: 1        -  (as `oc-core admin cell mode`: stored, the
 *                         part15, 2 part97)                 link dropped, the cell takes it at its next
 *                                                           HELLO and its calls end; a revoked cell:
 *                                                           invalid, nothing changed)
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
 * A read-only call that names no number and no cell, of one of the NOC's
 * poll operations (core.status, cell.status 0, cell.radio 0, reg.list 0,
 * cdr.recent, audit.list with no number, ocss.status, core.blocks; NOC
 * design §7) is audited once a minute per (operation, actor): the first
 * call as itself, the rest of that minute counted into one record,
 * "a<actor> <op> ok x<N> in 60 s". Any other call of one of these -
 * naming a cell, naming a cursor that targets one subscriber (reg.list's
 * after), naming a number, or failing - is audited as itself, never
 * folded into that count (quiet_op, final review Focus 3 / I1).
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
#define OC_API_REG_MAX   1000u
#define OC_API_AUDIT_MAX 500u

enum {
    OC_API_NUM_FREE = 0x01, OC_API_NUM_CHECK, OC_API_SUB_CREATE, OC_API_SUB_REISSUE, OC_API_SUB_STATUS,
    OC_API_SUB_RELEASE, OC_API_SUB_DISABLE, OC_API_SUB_ENABLE, OC_API_CDR_LIST, OC_API_CELL_ADD,
    OC_API_CELL_SET_CERT, OC_API_CELL_REVOKE, OC_API_CELL_STATUS, OC_API_CORE_STATUS, OC_API_ROUTE_OFFER,
    OC_API_CELL_RADIO, OC_API_REG_LIST, OC_API_CDR_RECENT, OC_API_AUDIT_LIST, OC_API_OCSS_STATUS,
    OC_API_CORE_BLOCKS, OC_API_CELL_MODE,
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

/* One OCSS peer as ocss.status shows it: the daemon fills these from its
 * OCSS links (oc_ocss, in oc_net, which oc_api does not link against). */
typedef struct {
    uint16_t core_id;
    uint8_t  dials; /* this core dials it */
    uint8_t  state; /* 0 down, 1 connecting, 2 handshake, 3 open, 4 up */
    uint32_t since, last_rx, last_tx; /* unix s; 0 never */
    uint32_t dropped; /* frames that did not decode, on its connection */
    char     addr[64]; /* "-": it dials this core */
} oc_api_peer_t;

/* The minute of a read-only operation's quiet audit (above). */
typedef struct {
    uint32_t actor;     /* whose minute it is */
    uint32_t n;         /* calls in it not audited one by one */
    uint64_t window_us; /* its end; 0: none open */
} oc_api_quiet_t;

typedef struct {
    oc_sql_t              *sql;
    const oc_core_route_t *route;
    const oc_core_cfg_t   *cfg;
    oc_core_t             *core;
    uint64_t (*now_us)(void);   /* monotonic: rate limits, uptime, oc_core's clock */
    uint32_t (*unix_now)(void); /* wall clock: token expiry, registration times */
    const char *name, *version; /* core.status */
    /* ocss.status: up to cap configured peers into out, how many; NULL: no OCSS */
    unsigned (*peers)(void *ctx, oc_api_peer_t *out, unsigned cap);
    void     *peers_ctx;
    uint64_t    started_us;
    oc_api_rate_t rate[OC_API_OPS];
    oc_api_quiet_t quiet[OC_API_OPS];
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
