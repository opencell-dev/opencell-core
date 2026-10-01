#define _GNU_SOURCE
/* oc-core: the network core daemon (network-core spec §4.2, §17 decisions
 * 1, 5, 8 and 9), and its admin client.
 *
 *   oc-core [--config FILE] [--key-file FILE] [--db PATH]
 *   oc-core admin [--socket PATH] [--config FILE] COMMAND...
 *   oc-core admin --offline [--config FILE] [--key-file FILE] [--db PATH] COMMAND...
 *   oc-core --version
 *
 * One thread: a poll() loop feeds oc_core the cells' frames and tick(now),
 * with SQLite on the same thread. Cells connect to cell_socket (the §6
 * Unix socket); `oc-core admin` talks to admin_socket, one command per
 * connection: the client sends its words, each ending in a NUL (as root
 * under sudo, led by its SUDO_UID: oc_admin_sudo_field), and shuts its
 * side; the daemon answers "<status> <bytes>\n" and the command's
 * output, which the client counts (a cut answer is a failure). The
 * master key comes from --key-file or the systemd credential master.key
 * ($CREDENTIALS_DIRECTORY). Logs go to stderr with journald priorities.
 *
 * Links: the daemon closes a link oc_core drops (io.close); a link whose
 * peer vanished, or whose send or read failed, is marked dead and oc_core
 * hears of it (oc_core_link_down) once the call in progress has returned.
 * On a stop every link goes down the same way before the database closes,
 * so the calls in progress end with their CDRs.
 * Reconnect backoff is the cell's business (oc_core.h, oc_core_tick): no
 * state here outlives a link.
 *
 * The admin API (portal spec §7, oc_api.h): with api_listen set, the portal
 * connects over TLS to that private address (oc_apisrv.h), in the same
 * loop; api_cert, api_key and api_ca are files, or - a value with no '/' -
 * systemd credentials by name ($CREDENTIALS_DIRECTORY). Every minute,
 * whether or not the API listens, unactivated numbers whose code has
 * expired are released (network-core spec §18.3, oc_api_tick).
 *
 * The test services and OCSS (core test services spec §5-§7): playback is
 * a second service number with a clip file (playback_clip, read once at
 * start); peer lines name the other cores (their pinned certificates, and
 * the address of each this core dials), ocss_listen where they reach this
 * one; a block line's third field is its home core. The loop's poll waits
 * no longer than oc_core_due, so a playback payload leaves on time. */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "oc_admin.h"
#include "oc_api.h"
#include "oc_apisrv.h"
#include "oc_conn.h"
#include "oc_core.h"
#include "oc_kv.h"
#include "oc_log.h"
#include "oc_ocss.h"
#include "oc_seal.h"
#include "oc_sig_keys.h"
#include "oc_sql.h"
#include "oc_tls.h"

#ifndef OC_VERSION
#define OC_VERSION "dev"
#endif

#define DEFAULT_CONFIG "/etc/opencell/oc-core.conf"
#define DEFAULT_ADMIN  "/run/opencell/admin.sock"
#define DAEMON_USER    "oc-core" /* the unit's User= */
#define ADMIN_REQ_MAX  4096u /* one command's words, NULs included */
#define ADMIN_ARGS_MAX 32
/* An admin peer has this long, in all, to send its request, and again to
 * take its answer; then it is dropped. The daemon serves nothing else
 * meanwhile (no tick, no cell), so the budget is per connection, not per
 * read or write: a peer dripping a byte at a time can't stretch it. */
#define ADMIN_IO_S     2
#define CLIENT_WAIT_S  30 /* the client waits this long for the answer */

typedef struct {
    int       used;
    uint32_t  id;   /* oc_core's link handle: never reused */
    int       dead; /* the peer vanished, or a send or read failed: oc_core hears of it after the call in progress */
    oc_conn_t c;
} dlink_t;

static struct {
    oc_kv_t         kv;
    oc_core_cfg_t   cfg;
    oc_core_route_t route;
    const char     *db, *cell_sock, *admin_sock;
    oc_sql_t       *sql;
    oc_core_t       core;
    int             cell_l, admin_l;
    dlink_t         link[OC_CORE_LINKS];
    uint32_t        next_id;
    uint8_t         key[32]; /* only until the database has its copy */
    char            name[64];
    oc_tls_cfg_t    tls_cfg; /* the admin API's, when api_listen is set */
    const char     *api_listen;
    oc_api_t        api;
    oc_apisrv_t     apisrv;
    oc_tls_t       *tls;
    uint8_t         clip[OC_CORE_CLIP_MAX]; /* the playback service's, from playback_clip */
    oc_ocss_cfg_t   ocss_cfg;               /* npeer 0: no OCSS */
    oc_ocss_t       ocss;
} D = { .cell_l = -1, .admin_l = -1, .apisrv = { .lfd = -1 }, .ocss = { .lfd = -1 } };

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static uint64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void urandom(uint8_t *out, size_t n)
{
    while (n > 0) {
        ssize_t r = getrandom(out, n, 0);
        if (r > 0) {
            out += r;
            n -= (size_t)r;
        }
    }
}

/* All of p to fd (a pipe, a socket, a terminal), with no stdio buffer
 * keeping a copy (an activation code, say). 0 or -1. */
static int write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* The daemon holds the master key for life, and --offline holds it too:
 * no core dump (systemd-coredump, a pipe core_pattern, which ignores
 * RLIMIT_CORE) and no ptrace by the same user. Before the key is read.
 * The unit adds LimitCORE=0. */
static void no_core_dumps(void)
{
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        oc_log(OC_LOG_WARNING, "prctl(PR_SET_DUMPABLE): %s: a core dump could hold the master key", strerror(errno));
    }
}

/* ---- configuration ---- */

static const char *const KEYS[] = { "core_id",      "key_id",       "echo",          "block",          "db",
                                    "cell_socket",  "cell_group",   "admin_socket",  "admin_group",    "name",
                                    "api_listen",   "api_cert",     "api_key",       "api_ca",         "api_portal_fpr",
                                    "api_rate",     "playback",     "playback_clip", "peer",           "ocss_listen",
                                    "ocss_cert",    "ocss_key",     "ocss_ca",       NULL };

/* playback_clip: read whole, checked as oc_core_clip_ok wants it. 0 or -1 (logged). */
static int load_clip(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        oc_log(OC_LOG_ERR, "config: playback_clip = '%s': %s", path, strerror(errno));
        return -1;
    }
    size_t n = fread(D.clip, 1, sizeof(D.clip), f);
    int more = fgetc(f) != EOF;
    fclose(f);
    if (more || !oc_core_clip_ok(D.clip, (uint32_t)n)) {
        oc_log(OC_LOG_ERR,
               "config: playback_clip = '%s': %zu%s bytes; it must be 1 to %u, a whole number of %u-byte payloads "
               "(headerless c2enc 1200 output: tools/clip/oc-clip-gen)",
               path, n, more ? "+" : "", OC_CORE_CLIP_MAX, OC_CORE_PLAY_BYTES);
        return -1;
    }
    D.cfg.clip = D.clip;
    D.cfg.clip_len = (uint32_t)n;
    return 0;
}

/* A service number (echo, playback) must be in a block this core is home
 * for: a number of another core's block would hide that core's subscriber. */
static int service_ok(const char *key, const uint8_t n[OC_SIG_NUMBER_LEN])
{
    if (oc_core_route_home(&D.route, oc_core_route_find(&D.route, n))) return 0;
    oc_log(OC_LOG_ERR, "config: %s = %s: not in a block this core is home for", key, oc_kv_get(&D.kv, key));
    return -1;
}

/* peer = CORE_ID ADDRESS|- SHA256: another core (core test services spec
 * §7.1); "-" when that core dials this one (it has the lower core_id). */
static int load_peers(void)
{
    oc_ocss_cfg_t *o = &D.ocss_cfg;
    memset(o, 0, sizeof(*o));
    for (unsigned i = 0; oc_kv_nth(&D.kv, "peer", i) != NULL; i++) {
        const char *v = oc_kv_nth(&D.kv, "peer", i);
        char addr[64], hex[80], extra;
        unsigned id;
        if (i >= OC_OCSS_PEERS || sscanf(v, "%u %63s %79s %c", &id, addr, hex, &extra) != 3 || id == 0 || id > 65535 ||
            id == D.cfg.core_id || oc_tls_fpr_parse(hex, o->peer[i].fpr) != 0) {
            oc_log(OC_LOG_ERR,
                   "config: peer = '%s': CORE_ID ADDRESS|- SHA256, e.g. peer = 2 10.99.0.2:7443 <64 hex digits> "
                   "(another core; at most %u)", v, OC_OCSS_PEERS);
            return -1;
        }
        for (unsigned j = 0; j < i; j++) {
            if (o->peer[j].core_id == id) {
                oc_log(OC_LOG_ERR, "config: peer %u is named twice", id);
                return -1;
            }
            if (memcmp(o->peer[j].fpr, o->peer[i].fpr, 32) == 0) { /* review M2 */
                oc_log(OC_LOG_ERR, "config: peer %u and peer %u have the same certificate fingerprint",
                       o->peer[j].core_id, id);
                return -1;
            }
        }
        /* review M2 (spec §7.1): the lower core_id dials, so an address
         * names a peer with a higher id, "-" one with a lower id. */
        int has_addr = strcmp(addr, "-") != 0;
        if ((id < D.cfg.core_id) == has_addr) {
            oc_log(OC_LOG_ERR, "config: peer %u: the lower core_id dials; %s", id,
                   id < D.cfg.core_id ? "give '-' here, not an address (that core dials this one)"
                                      : "give its address here (this core dials it)");
            return -1;
        }
        o->peer[i].core_id = (uint16_t)id;
        if (has_addr) snprintf(o->peer[i].addr, sizeof(o->peer[i].addr), "%s", addr);
        o->npeer = i + 1u;
    }
    for (unsigned i = 0; i < D.route.n; i++) { /* every block homed elsewhere needs its home as a peer */
        const oc_core_block_t *b = &D.route.b[i];
        int known = b->home_core == D.cfg.core_id;
        for (unsigned j = 0; j < o->npeer; j++) known |= o->peer[j].core_id == b->home_core;
        if (!known) {
            oc_log(OC_LOG_ERR, "config: block %s is homed on core %u: add a peer = %u ... line", b->prefix,
                   b->home_core, b->home_core);
            return -1;
        }
    }
    const char *keys[] = { "ocss_cert", "ocss_key", "ocss_ca" };
    for (unsigned i = 0; i < 3; i++) {
        if ((o->npeer > 0) != (oc_kv_get(&D.kv, keys[i]) != NULL)) {
            oc_log(OC_LOG_ERR, o->npeer > 0 ? "config: a peer is set: %s is needed too"
                                            : "config: %s is set but no peer is (OCSS would not run)", keys[i]);
            return -1;
        }
    }
    int dials_us = 0;
    for (unsigned j = 0; j < o->npeer; j++) dials_us |= o->peer[j].addr[0] == '\0';
    if (dials_us && oc_kv_get(&D.kv, "ocss_listen") == NULL) {
        oc_log(OC_LOG_ERR, "config: a peer dials this core (address -): ocss_listen is needed");
        return -1;
    }
    if (o->npeer == 0 && oc_kv_get(&D.kv, "ocss_listen") != NULL) {
        oc_log(OC_LOG_ERR, "config: ocss_listen is set but no peer is");
        return -1;
    }
    return 0;
}

static int load_config(const char *path, const char *db)
{
    long long v;
    if (oc_kv_load(&D.kv, path) != 0 || !oc_kv_known(&D.kv, KEYS)) {
        oc_log(OC_LOG_ERR, "config: %s", D.kv.err);
        return -1;
    }
    memset(&D.cfg, 0, sizeof(D.cfg));
    if (oc_kv_num(&D.kv, "core_id", 1, 65535, 1, &v) != 0) goto bad;
    D.cfg.core_id = (uint16_t)v;
    if (oc_kv_num(&D.kv, "key_id", 1, 65535, 1, &v) != 0) goto bad;
    D.cfg.key_id = (uint16_t)v;
    const char *echo = oc_kv_get(&D.kv, "echo");
    if (echo == NULL) echo = "+883160655500100";
    if (oc_sig_number_normalize(echo, strlen(echo), NULL, D.cfg.echo_number) != 0) {
        oc_log(OC_LOG_ERR, "config: echo = '%s': a full OpenCell number", echo);
        return -1;
    }
    oc_core_route_init(&D.route, D.cfg.core_id);
    for (unsigned i = 0; oc_kv_nth(&D.kv, "block", i) != NULL; i++) {
        char prefix[32], extra;
        unsigned idx, home = D.cfg.core_id;
        const char *b = oc_kv_nth(&D.kv, "block", i);
        int got = sscanf(b, "%31s %u %u %c", prefix, &idx, &home, &extra);
        if ((got != 2 && got != 3) || idx > 65535 || home == 0 || home > 65535 ||
            oc_core_route_add(&D.route, prefix, (uint16_t)idx, (uint16_t)home) != 0) {
            oc_log(OC_LOG_ERR,
                   "config: block = '%s': PREFIX INDEX [HOME_CORE], e.g. 8831606 1 (a new prefix and index; "
                   "HOME_CORE: another core's block, reached over OCSS)", b);
            return -1;
        }
    }
    int home_blocks = 0;
    for (unsigned i = 0; i < D.route.n; i++) home_blocks += D.route.b[i].home_core == D.cfg.core_id;
    if (home_blocks == 0) {
        oc_log(OC_LOG_ERR, "config: no block this core is home for: add e.g. block = 8831606 1");
        return -1;
    }
    if (service_ok("echo", D.cfg.echo_number) != 0) return -1;
    const char *play = oc_kv_get(&D.kv, "playback"), *clip = oc_kv_get(&D.kv, "playback_clip");
    if ((play == NULL) != (clip == NULL)) {
        oc_log(OC_LOG_ERR, "config: playback and playback_clip go together (the number and its clip)");
        return -1;
    }
    if (play != NULL) {
        if (oc_sig_number_normalize(play, strlen(play), NULL, D.cfg.playback_number) != 0 ||
            memcmp(D.cfg.playback_number, D.cfg.echo_number, OC_SIG_NUMBER_LEN) == 0) {
            oc_log(OC_LOG_ERR, "config: playback = '%s': a full OpenCell number, not the echo service's", play);
            return -1;
        }
        if (service_ok("playback", D.cfg.playback_number) != 0 || load_clip(clip) != 0) return -1;
    }
    if (load_peers() != 0) return -1;
    D.db = db != NULL ? db : oc_kv_get(&D.kv, "db") ? oc_kv_get(&D.kv, "db") : "/var/lib/opencell/core/core.db";
    D.cell_sock = oc_kv_get(&D.kv, "cell_socket") ? oc_kv_get(&D.kv, "cell_socket") : "/run/opencell/core.sock";
    D.admin_sock = oc_kv_get(&D.kv, "admin_socket") ? oc_kv_get(&D.kv, "admin_socket") : DEFAULT_ADMIN;
    snprintf(D.name, sizeof(D.name), "%s", oc_kv_get(&D.kv, "name") ? oc_kv_get(&D.kv, "name") : "");
    if (D.name[0] == '\0') snprintf(D.name, sizeof(D.name), "oc-core-%u", D.cfg.core_id);
    /* the admin API: all of it or none */
    memset(&D.tls_cfg, 0, sizeof(D.tls_cfg));
    D.api_listen = oc_kv_get(&D.kv, "api_listen");
    if (D.api_listen != NULL) {
        struct sockaddr_storage sa;
        socklen_t len;
        char err[200];
        if (oc_apisrv_addr(D.api_listen, &sa, &len, err, sizeof(err)) != 0) {
            oc_log(OC_LOG_ERR, "config: %s", err);
            return -1;
        }
    }
    const char *api_keys[] = { "api_cert", "api_key", "api_ca", "api_portal_fpr" };
    for (unsigned i = 0; i < 4; i++) {
        if (D.api_listen != NULL && oc_kv_get(&D.kv, api_keys[i]) == NULL) {
            oc_log(OC_LOG_ERR, "config: api_listen is set: %s is needed too", api_keys[i]);
            return -1;
        }
    }
    if (D.api_listen == NULL && (oc_kv_get(&D.kv, "api_cert") || oc_kv_get(&D.kv, "api_key") ||
                                 oc_kv_get(&D.kv, "api_ca") || oc_kv_get(&D.kv, "api_portal_fpr"))) {
        oc_log(OC_LOG_ERR, "config: api_* is set but api_listen is not (the admin API would not listen)");
        return -1;
    }
    for (unsigned i = 0; oc_kv_nth(&D.kv, "api_portal_fpr", i) != NULL; i++) {
        const char *f = oc_kv_nth(&D.kv, "api_portal_fpr", i);
        if (i >= OC_TLS_PINS || oc_tls_fpr_parse(f, D.tls_cfg.pin[i]) != 0) {
            oc_log(OC_LOG_ERR, "config: api_portal_fpr = '%s': at most %u, each 64 hex digits (oc-ca fpr CERT)", f,
                   OC_TLS_PINS);
            return -1;
        }
        D.tls_cfg.npin = i + 1u;
    }
    return 0;
bad:
    oc_log(OC_LOG_ERR, "config: %s", D.kv.err);
    return -1;
}

static int load_key(const char *key_file)
{
    char path[512], err[600];
    if (key_file == NULL) {
        const char *dir = getenv("CREDENTIALS_DIRECTORY");
        if (dir == NULL) {
            oc_log(OC_LOG_ERR, "no master key: give --key-file, or run under systemd with LoadCredential=master.key");
            return -1;
        }
        snprintf(path, sizeof(path), "%s/master.key", dir);
        key_file = path;
    }
    if (oc_key_load(key_file, D.key, err, sizeof(err)) != 0) {
        oc_log(OC_LOG_ERR, "%s", err);
        return -1;
    }
    return 0;
}

/* Opens the database with the master key, which is then wiped here: the
 * store keeps its own copy. */
static int open_db(void)
{
    char err[700];
    oc_sql_cfg_t c = { D.db, D.key, urandom, NULL, 0 };
    D.sql = oc_sql_open(&c, err, sizeof(err));
    oc_sig_wipe(D.key, sizeof(D.key));
    if (D.sql == NULL) {
        oc_log(OC_LOG_ERR, "%s", err);
        return -1;
    }
    if (oc_sql_backup(D.sql)[0] != '\0') {
        oc_log(OC_LOG_NOTICE, "database migrated to v%d; the old one is kept as %s", oc_sql_version(D.sql),
               oc_sql_backup(D.sql));
    }
    return 0;
}

/* A config value naming a file: as it is, or with no '/', a systemd
 * credential (LoadCredential=NAME:PATH) in $CREDENTIALS_DIRECTORY. */
static const char *cred_path(const char *v, char *buf, size_t cap)
{
    const char *dir = getenv("CREDENTIALS_DIRECTORY");
    if (strchr(v, '/') != NULL || dir == NULL) return v;
    snprintf(buf, cap, "%s/%s", dir, v);
    return buf;
}

static uint32_t unix_now(void) { return (uint32_t)time(NULL); }

/* ocss.status (oc_api.h): each configured peer, from the core's view of
 * its link once it is up, else from the transport's (connecting,
 * handshake, open). Monotonic times become unix seconds. */
static unsigned api_peers(void *ctx, oc_api_peer_t *out, unsigned cap)
{
    (void)ctx;
    uint64_t now = mono_us();
    uint32_t wall = unix_now();
    unsigned n = 0;
#define OC_WALL(t) ((t) == 0 || (t) > now ? 0u : wall - (uint32_t)((now - (t)) / 1000000u))
    for (unsigned i = 0; i < D.ocss_cfg.npeer && n < cap; i++) {
        const oc_ocss_peer_t *p = &D.ocss_cfg.peer[i];
        oc_api_peer_t *o = &out[n++];
        memset(o, 0, sizeof(*o));
        o->core_id = p->core_id;
        o->dials = p->addr[0] != '\0';
        snprintf(o->addr, sizeof(o->addr), "%s", p->addr[0] != '\0' ? p->addr : "-");
        for (unsigned c = 0; c < OC_OCSS_CONNS; c++) {
            const oc_ocss_conn_t *k = &D.ocss.c[c];
            if (k->state == 0 || k->core_id != p->core_id) continue;
            o->state = (uint8_t)k->state;
            o->since = OC_WALL(k->since_us);
            o->dropped = k->bad;
        }
        for (unsigned c = 0; c < OC_CORE_PEERS; c++) {
            const oc_core_peer_t *k = &D.core.peers[c];
            if (!k->used || !k->up || k->core_id != p->core_id) continue;
            o->state = 4;
            o->since = OC_WALL(k->since);
            o->last_rx = OC_WALL(k->last_rx);
            o->last_tx = OC_WALL(k->last_tx);
        }
    }
#undef OC_WALL
    return n;
}

/* The admin API's state (always: its expiry job runs without a listener
 * too) and, with api_listen, its TLS listener. 0 or -1 (logged). */
static int api_start(void)
{
    char err[400], cert[512], key[512], ca[512];
    memset(&D.api, 0, sizeof(D.api));
    D.api.sql = D.sql;
    D.api.route = &D.route;
    D.api.cfg = &D.cfg;
    D.api.core = &D.core;
    D.api.now_us = mono_us;
    D.api.unix_now = unix_now;
    D.api.name = D.name;
    D.api.version = OC_VERSION;
    D.api.peers = api_peers;
    oc_api_init(&D.api);
    for (unsigned i = 0; oc_kv_nth(&D.kv, "api_rate", i) != NULL; i++) {
        if (oc_api_rate_set(&D.api, oc_kv_nth(&D.kv, "api_rate", i), err, sizeof(err)) != 0) {
            oc_log(OC_LOG_ERR, "config: %s", err);
            return -1;
        }
    }
    if (D.api_listen == NULL) return 0;
    D.tls_cfg.cert = cred_path(oc_kv_get(&D.kv, "api_cert"), cert, sizeof(cert));
    D.tls_cfg.key = cred_path(oc_kv_get(&D.kv, "api_key"), key, sizeof(key));
    D.tls_cfg.ca = cred_path(oc_kv_get(&D.kv, "api_ca"), ca, sizeof(ca));
    D.tls_cfg.alpn = "oc-admin/1";
    D.tls_cfg.role = OC_TLS_ROLE_PORTAL;
    D.tls = oc_tls_new(&D.tls_cfg, err, sizeof(err));
    if (D.tls == NULL) {
        oc_log(OC_LOG_ERR, "admin API: %s", err);
        return -1;
    }
    if (oc_apisrv_open(&D.apisrv, D.api_listen, D.tls, &D.api, mono_us, err, sizeof(err)) != 0) {
        oc_log(OC_LOG_ERR, "config: %s", err);
        return -1;
    }
    return 0;
}

/* OCSS (core test services spec §6): the links to the other cores, with
 * the ocss_* files as the admin API's are given (a value with no '/' is a
 * systemd credential). 0, or -1 (logged). */
static uint32_t ocss_new_link(void *ctx)
{
    (void)ctx;
    return ++D.next_id;
}

static int ocss_start(void)
{
    char err[400], cert[512], key[512], ca[512];
    if (D.ocss_cfg.npeer == 0) return 0;
    D.ocss_cfg.listen = oc_kv_get(&D.kv, "ocss_listen");
    D.ocss_cfg.cert = cred_path(oc_kv_get(&D.kv, "ocss_cert"), cert, sizeof(cert));
    D.ocss_cfg.key = cred_path(oc_kv_get(&D.kv, "ocss_key"), key, sizeof(key));
    D.ocss_cfg.ca = cred_path(oc_kv_get(&D.kv, "ocss_ca"), ca, sizeof(ca));
    D.ocss_cfg.core = &D.core;
    D.ocss_cfg.now_us = mono_us;
    D.ocss_cfg.new_link = ocss_new_link;
    if (oc_ocss_open(&D.ocss, &D.ocss_cfg, err, sizeof(err)) != 0) {
        oc_log(OC_LOG_ERR, "OCSS: %s", err);
        return -1;
    }
    return 0;
}

/* ---- oc_core's transport ---- */

static dlink_t *dlink(uint32_t id)
{
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used && D.link[i].id == id) return &D.link[i];
    }
    return NULL;
}

static int k_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    if (oc_ocss_owns(&D.ocss, link)) return oc_ocss_send(&D.ocss, link, m);
    dlink_t *l = dlink(link);
    if (l == NULL || l->dead) return -1;
    if (oc_conn_send(&l->c, m) != 0) {
        oc_log(OC_LOG_WARNING, "link %u: send failed (the cell stopped reading): dropped", (unsigned)link);
        oc_conn_close(&l->c);
        l->dead = 1;
        return -1;
    }
    return 0;
}

static void k_close(void *c, uint32_t link) /* oc_core dropped it: no oc_core_link_down */
{
    (void)c;
    if (oc_ocss_owns(&D.ocss, link)) {
        oc_ocss_drop(&D.ocss, link);
        return;
    }
    dlink_t *l = dlink(link);
    if (l == NULL) return;
    oc_conn_flush(&l->c); /* a HELLO_NAK goes out before the close */
    oc_conn_close(&l->c);
    l->used = 0;
}

static void k_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    urandom(out, n);
}

static uint32_t k_unix(void *c)
{
    (void)c;
    return (uint32_t)time(NULL);
}

static void on_frame(void *ctx, const oc_core_msg_t *m)
{
    dlink_t *l = ctx;
    if (!l->dead) oc_core_rx(&D.core, l->id, m, mono_us());
}

/* A dead link: closed, and oc_core hears of it (its calls end). Called
 * from the loop only, never from inside an oc_core call. */
static void link_lost(dlink_t *l)
{
    uint32_t id = l->id;
    oc_conn_close(&l->c);
    l->used = 0;
    oc_core_link_down(&D.core, id, mono_us());
}

/* `cell mode`: the cell's link is dropped (it reconnects to take its new
 * mode). Marked dead here, inside the admin command; the loop closes it and
 * tells oc_core right after. */
static void drop_cell(void *ctx, uint32_t cell_id)
{
    (void)ctx;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (!D.core.links[i].used || D.core.links[i].cell_id != cell_id) continue;
        dlink_t *l = dlink(D.core.links[i].link);
        if (l != NULL) l->dead = 1;
    }
}

/* Stopping: every live link goes down in oc_core while the store is still
 * open, so each call in progress ends (cause 5, network-core spec §7.6,
 * §7.10) and its CDR is written (§3); a CALL_RELEASE this queues for a
 * leg on another link goes out if the socket takes it now. The links are
 * closed after. */
static void links_down(void)
{
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used) oc_core_link_down(&D.core, D.link[i].id, mono_us());
    }
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used && !D.link[i].dead) oc_conn_flush(&D.link[i].c);
    }
}

static void accept_cell(void)
{
    int fd = accept4(D.cell_l, NULL, NULL, SOCK_CLOEXEC);
    if (fd < 0) return;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used) continue;
        dlink_t *l = &D.link[i];
        memset(l, 0, sizeof(*l));
        l->used = 1;
        l->id = ++D.next_id;
        oc_conn_init(&l->c, fd);
        oc_core_link_up(&D.core, l->id, mono_us());
        return;
    }
    oc_log(OC_LOG_WARNING, "cell socket: %u links already, connection refused", OC_CORE_LINKS);
    close(fd);
}

/* ---- the admin socket ---- */

/* Why an admin peer's I/O stopped. */
enum { AIO_OK = 0, AIO_LATE, AIO_STOP, AIO_CLOSED, AIO_ERROR };

static const char *aio_why(int why, int err, char *buf, size_t cap)
{
    switch (why) {
    case AIO_LATE: snprintf(buf, cap, "it took more than %d s", ADMIN_IO_S); break;
    case AIO_STOP: snprintf(buf, cap, "oc-core is stopping"); break;
    case AIO_CLOSED: snprintf(buf, cap, "the peer closed its connection"); break;
    default: snprintf(buf, cap, "%s", strerror(err)); break;
    }
    return buf;
}

/* Waits for fd to be ready for ev: AIO_OK, AIO_LATE at the deadline
 * (mono_us), AIO_STOP once SIGTERM has come (the poll is interrupted, and
 * the stop wins), or AIO_ERROR with errno. */
static int admin_wait(int fd, short ev, uint64_t deadline)
{
    for (;;) {
        uint64_t now = mono_us();
        if (g_stop) return AIO_STOP;
        if (now >= deadline) return AIO_LATE;
        struct pollfd p = { fd, ev, 0 };
        int r = poll(&p, 1, (int)((deadline - now + 999u) / 1000u));
        if (r > 0) return AIO_OK;
        if (r < 0 && errno != EINTR) return AIO_ERROR;
    }
}

/* All of p to the admin peer before the deadline: AIO_OK, or why not
 * (*err: the errno of AIO_ERROR). */
static int admin_send(int fd, const char *p, size_t n, uint64_t deadline, int *err)
{
    while (n > 0) {
        int why = admin_wait(fd, POLLOUT, deadline);
        if (why != AIO_OK) {
            *err = errno;
            return why;
        }
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (w < 0 && (errno == EPIPE || errno == ECONNRESET)) return AIO_CLOSED;
        if (w <= 0) {
            *err = w < 0 ? errno : EIO;
            return AIO_ERROR;
        }
        p += w;
        n -= (size_t)w;
    }
    return AIO_OK;
}

static void serve_admin(void)
{
    int fd = accept4(D.admin_l, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (fd < 0) return;
    struct ucred cr;
    socklen_t cl = sizeof(cr);
    char req[ADMIN_REQ_MAX + 1], what[48];
    size_t n = 0;
    int rc, cut = 0;
    uint64_t deadline = mono_us() + ADMIN_IO_S * 1000000ull;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0) cr.uid = (uid_t)-1;
    for (;;) {
        int why = admin_wait(fd, POLLIN, deadline);
        if (why != AIO_OK) {
            /* Too slow, oc-core is stopping, or poll failed: dropped unanswered, nothing run. */
            char b[80];
            oc_log(why == AIO_STOP ? OC_LOG_INFO : OC_LOG_WARNING, "admin (uid %u): the request was dropped: %s",
                   (unsigned)cr.uid, aio_why(why, errno, b, sizeof(b)));
            oc_sig_wipe(req, sizeof(req));
            close(fd);
            return;
        }
        ssize_t r = recv(fd, req + n, ADMIN_REQ_MAX + 1u - n, 0);
        if (r < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (r < 0) cut = 1; /* a read error: the words may be incomplete */
        if (r <= 0) break;
        n += (size_t)r;
        if (n > ADMIN_REQ_MAX) {
            cut = 1;
            break;
        }
    }
    /* A root client under sudo leads with its SUDO_UID (oc_admin.h): not
     * one of the command's words. */
    uint32_t sudo = 0;
    int bad_sudo = 0;
    size_t start = 0;
    if (!cut && n > 0 && memchr(req, '\0', n) != NULL) {
        int f = oc_admin_sudo_field(req, (uint32_t)cr.uid, &sudo);
        bad_sudo = f < 0;
        if (f == 1) start = strlen(req) + 1u;
    }
    char *argv[ADMIN_ARGS_MAX];
    int argc = 0;
    for (size_t i = start; !cut && !bad_sudo && i < n; i += strlen(req + i) + 1u) {
        if (argc == ADMIN_ARGS_MAX || memchr(req + i, '\0', n - i) == NULL) {
            cut = 1; /* too many words, or the last without its NUL */
            break;
        }
        argv[argc++] = req + i;
    }
    oc_buf_t out = { 0 };
    char who[48];
    if (sudo != 0) {
        snprintf(who, sizeof(who), "uid %u, sudo u%u", (unsigned)cr.uid, (unsigned)sudo);
    } else {
        snprintf(who, sizeof(who), "uid %u", (unsigned)cr.uid);
    }
    if (bad_sudo) {
        /* A leading --word is only ever root's sudo field; from anyone else,
         * or malformed, the request is refused whole, nothing run - and,
         * a security event, written to the audit log. */
        rc = 2;
        snprintf(what, sizeof(what), "(a request with a bad --word)");
        oc_log(OC_LOG_WARNING, "admin (%s): %s: refused", who,
               cr.uid == 0 ? "a malformed sudo field or unknown --word" : "a --word from a peer that is not root");
        oc_buf_printf(&out, "the request's leading --word is not a sudo field, or its peer is not root\n");
        oc_core_audit_t r;
        memset(&r, 0, sizeof(r));
        r.ts = (uint32_t)time(NULL);
        r.event = OC_CORE_AUDIT_ADMIN;
        snprintf(r.detail, sizeof(r.detail), "refused: %s--word from u%u", cr.uid == 0 ? "bad " : "",
                 (unsigned)cr.uid);
        oc_core_store_t st = oc_sql_store(D.sql);
        if (st.audit_add(st.ctx, &r) != 0) oc_log(OC_LOG_ERR, "admin: audit write FAILED");
    } else if (cut) {
        /* Never run part of a command: its first words may be another one. */
        rc = 2;
        snprintf(what, sizeof(what), "(a request that is cut short or too long)");
        oc_buf_printf(&out, "the request was cut short or is too long (at most %u bytes, %d words)\n", ADMIN_REQ_MAX,
                      ADMIN_ARGS_MAX);
    } else {
        oc_admin_t a;
        memset(&a, 0, sizeof(a));
        a.sql = D.sql;
        a.route = &D.route;
        a.cfg = &D.cfg;
        a.core = &D.core;
        a.random = urandom;
        a.now_us = mono_us;
        a.drop_cell = drop_cell;
        a.uid = (uint32_t)cr.uid;
        a.sudo_uid = sudo;
        rc = oc_admin_run(&a, argc, argv, &out); /* audited there, the words cleaned */
        snprintf(what, sizeof(what), "%s%s", argc > 0 ? argv[0] : "", argc > 1 ? " ..." : "");
    }
    oc_log_clean(what); /* the peer's words: no line of their own in the journal */
    oc_log(OC_LOG_INFO, "admin (%s): %s -> %d%s", who, what, rc, out.err ? " (output cut)" : "");
    /* The head carries the answer's size, so a peer can tell a cut one (a
     * drop at the deadline) from a whole one. rc is 1 when the output could
     * not be made whole (oc_admin.h): what there is goes out, marked failed. */
    size_t len = out.p != NULL ? out.n : 0;
    char head[32];
    int hn = snprintf(head, sizeof(head), "%d %zu\n", rc, len);
    deadline = mono_us() + ADMIN_IO_S * 1000000ull; /* the answer's own budget */
    int err = 0, why = admin_send(fd, head, (size_t)hn, deadline, &err);
    if (why == AIO_OK && len > 0) why = admin_send(fd, out.p, len, deadline, &err);
    if (why != AIO_OK) {
        char b[80];
        oc_log(why == AIO_STOP ? OC_LOG_INFO : OC_LOG_WARNING, "admin (%s): the answer was dropped: %s", who,
               aio_why(why, err, b, sizeof(b)));
    }
    oc_buf_free(&out);        /* wiped */
    oc_sig_wipe(req, sizeof(req)); /* the words (an import path, a number) */
    close(fd);
}

/* ---- the daemon ---- */

static int listen_on(const char *path, const char *group)
{
    int fd = oc_unix_listen(path, group != NULL ? 0660 : 0600, group);
    if (fd < 0) {
        if (group != NULL && errno == ENOENT) {
            oc_log(OC_LOG_ERR, "%s: can't give it group '%s' (no such group?)", path, group);
        } else {
            oc_log(OC_LOG_ERR, "%s: %s", path, strerror(errno));
        }
    }
    return fd;
}

static int run_daemon(const char *config, const char *key_file, const char *db)
{
    int rc = 1;
    if (load_config(config, db) != 0 || load_key(key_file) != 0 || open_db() != 0) goto out;
    oc_core_store_t st = oc_sql_store(D.sql);
    const oc_core_io_t io = { NULL, k_send, k_close, k_random, k_unix, oc_log_line };
    if (oc_core_init(&D.core, &io, &st, &D.route, &D.cfg) != 0) {
        oc_log(OC_LOG_ERR,
               "network key %u can't be read from %s: if it was never made, run `oc-core admin --offline net init`",
               D.cfg.key_id, D.db);
        goto out;
    }
    D.cell_l = listen_on(D.cell_sock, oc_kv_get(&D.kv, "cell_group"));
    if (D.cell_l < 0) goto out;
    D.admin_l = listen_on(D.admin_sock, oc_kv_get(&D.kv, "admin_group"));
    if (D.admin_l < 0) goto out;
    if (api_start() != 0 || ocss_start() != 0) goto out;
    oc_log(OC_LOG_NOTICE,
           "oc-core %s: core %u (%s), key %u, %u blocks, db %s (v%d), cells on %s, admin on %s, API %s, "
           "playback %s, OCSS %u peers%s%s",
           OC_VERSION, D.cfg.core_id, D.name, D.cfg.key_id, D.route.n, D.db, oc_sql_version(D.sql), D.cell_sock,
           D.admin_sock, D.api_listen != NULL ? D.api_listen : "off", D.cfg.clip_len != 0 ? "on" : "off",
           D.ocss_cfg.npeer, D.ocss_cfg.listen != NULL ? ", listening on " : "",
           D.ocss_cfg.listen != NULL ? D.ocss_cfg.listen : "");
    while (!g_stop) {
        struct pollfd p[2 + OC_CORE_LINKS + 1 + OC_APISRV_CONNS + 1 + OC_OCSS_CONNS];
        dlink_t *who[2 + OC_CORE_LINKS];
        nfds_t np = 0;
        p[np] = (struct pollfd){ D.cell_l, POLLIN, 0 };
        who[np++] = NULL;
        p[np] = (struct pollfd){ D.admin_l, POLLIN, 0 };
        who[np++] = NULL;
        for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
            dlink_t *l = &D.link[i];
            if (!l->used || l->dead) continue;
            p[np] = (struct pollfd){ l->c.fd, (short)(POLLIN | (l->c.tn > 0 ? POLLOUT : 0)), 0 };
            who[np++] = l;
        }
        int timeout = 100; /* oc_core_tick at least every 100 ms (CELL_CFG retries, PING, timers) */
        uint64_t due = oc_core_due(&D.core), now = mono_us();
        if (due <= now) {
            timeout = 0;
        } else if (due - now < 100000u) {
            timeout = (int)((due - now + 999u) / 1000u); /* a playback payload: on time, to the ms */
        }
        nfds_t api_at = np;
        unsigned api_n = oc_apisrv_fds(&D.apisrv, p + np, &timeout);
        np += api_n;
        nfds_t ocss_at = np;
        unsigned ocss_n = oc_ocss_fds(&D.ocss, p + np, &timeout);
        np += ocss_n;
        int r = poll(p, np, timeout);
        if (r < 0 && errno != EINTR) {
            oc_log(OC_LOG_ERR, "poll: %s", strerror(errno));
            break;
        }
        if (r > 0) {
            if (p[0].revents & POLLIN) accept_cell();
            if (p[1].revents & POLLIN) serve_admin();
            for (nfds_t i = 2; i < api_at; i++) {
                dlink_t *l = who[i];
                if (!l->used || l->dead) continue; /* oc_core dropped it, or a send failed, meanwhile */
                if ((p[i].revents & POLLOUT) && oc_conn_flush(&l->c) != 0) {
                    l->dead = 1;
                    continue;
                }
                /* A read hands every whole frame to oc_core first: what a
                 * cell sent before it hung up is served. */
                if ((p[i].revents & (POLLIN | POLLHUP | POLLERR)) && oc_conn_read(&l->c, on_frame, l) != 0 &&
                    l->used) {
                    l->dead = 1;
                }
            }
        }
        if (r < 0) {
            for (nfds_t i = api_at; i < np; i++) p[i].revents = 0;
        }
        oc_apisrv_serve(&D.apisrv, p + api_at, api_n); /* deadlines too, so every turn */
        oc_ocss_serve(&D.ocss, p + ocss_at, ocss_n);   /* dials and deadlines too */
        oc_core_tick(&D.core, mono_us());
        oc_api_tick(&D.api);
        for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
            if (D.link[i].used && D.link[i].dead) link_lost(&D.link[i]);
        }
    }
    oc_log(OC_LOG_NOTICE, "oc-core: stopping");
    oc_apisrv_close(&D.apisrv);
    oc_ocss_close(&D.ocss); /* its calls end with their CDRs, the cells' legs released */
    links_down();
    rc = 0;
out:
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used) oc_conn_close(&D.link[i].c);
    }
    if (D.cell_l >= 0) {
        close(D.cell_l);
        unlink(D.cell_sock);
    }
    if (D.admin_l >= 0) {
        close(D.admin_l);
        unlink(D.admin_sock);
    }
    oc_apisrv_close(&D.apisrv);
    oc_ocss_close(&D.ocss);
    oc_tls_free(D.tls);
    if (D.sql != NULL) oc_sql_close(D.sql);
    oc_sig_wipe(D.key, sizeof(D.key));
    return rc;
}

/* ---- oc-core admin ---- */

/* Offline, run as root: the key is read first, then the process becomes
 * the owner of the database's directory, so the files it makes are the
 * daemon's. */
static int drop_to_db_owner(void)
{
    char buf[512];
    struct stat st;
    if (geteuid() != 0) return 0;
    snprintf(buf, sizeof(buf), "%s", D.db);
    const char *dir = dirname(buf);
    if (stat(dir, &st) != 0) {
        oc_log(OC_LOG_ERR, "%s: %s", dir, strerror(errno));
        return -1;
    }
    if (st.st_uid == 0) return 0;
    if (setgroups(0, NULL) != 0 || setgid(st.st_gid) != 0 || setuid(st.st_uid) != 0) {
        oc_log(OC_LOG_ERR, "can't become the database's owner (uid %u)", (unsigned)st.st_uid);
        return -1;
    }
    no_core_dumps(); /* the uid change set dumpable back to fs.suid_dumpable */
    return 0;
}

/* A directory made here, given its mode (and owner) through an fd opened
 * without following a symlink, so a link put in its place can't redirect
 * the chmod or chown. 0 made, 1 there already, -1 failed (logged). */
static int make_dir(int parent, const char *path, const char *name, mode_t mode, uid_t uid, gid_t gid)
{
    if (mkdirat(parent, name, 0700) != 0) {
        if (errno == EEXIST) return 1;
        oc_log(OC_LOG_ERR, "%s: %s", path, strerror(errno));
        return -1;
    }
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fchmod(fd, mode) != 0 || (uid != (uid_t)-1 && fchown(fd, uid, gid) != 0)) {
        oc_log(OC_LOG_ERR, "%s: %s", path, strerror(errno));
        if (fd >= 0) close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* First setup on a fresh machine: the database's directory (the unit's
 * StateDirectory, which systemd makes only when the unit first starts) is
 * made if missing - 0700, and as root owned by DAEMON_USER, as systemd
 * would make it; missing parents 0755 whatever the umask (a root umask of
 * 077 must not leave the daemon unable to reach its directory). An
 * existing directory is left as it is. 0 or -1. */
static int make_db_dir(void)
{
    char buf[512];
    struct stat st;
    snprintf(buf, sizeof(buf), "%s", D.db);
    char *dir = dirname(buf);
    if (stat(dir, &st) == 0) return 0;
    if (errno != ENOENT) {
        oc_log(OC_LOG_ERR, "%s: %s", dir, strerror(errno));
        return -1;
    }
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    if (geteuid() == 0) {
        struct passwd *pw = getpwnam(DAEMON_USER);
        if (pw == NULL) {
            oc_log(OC_LOG_WARNING, "%s: there is no user %s: made root's", dir, DAEMON_USER);
        } else {
            uid = pw->pw_uid;
            gid = pw->pw_gid;
        }
    }
    /* Walk it from the top (or from "."), each step from its parent's fd. */
    int at = open(dir[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (at < 0) {
        oc_log(OC_LOG_ERR, "%s: %s", dir, strerror(errno));
        return -1;
    }
    int rc = -1;
    char walk[512], *save = NULL;
    snprintf(walk, sizeof(walk), "%s", dir);
    for (char *name = strtok_r(walk, "/", &save); name != NULL;) {
        char *next_name = strtok_r(NULL, "/", &save);
        int last = next_name == NULL;
        if (make_dir(at, dir, name, last ? 0700 : 0755, last ? uid : (uid_t)-1, last ? gid : (gid_t)-1) < 0) break;
        if (last) { /* made, or made meanwhile by someone else: left as it is */
            rc = 0;
            break;
        }
        int next = openat(at, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC); /* an existing parent may be a link */
        if (next < 0) {
            oc_log(OC_LOG_ERR, "%s: %s", dir, strerror(errno));
            break;
        }
        close(at);
        at = next;
        name = next_name;
    }
    close(at);
    if (rc == 0) oc_log(OC_LOG_NOTICE, "%s made (0700)", dir);
    return rc;
}

/* Under sudo, the operator behind uid 0 (sudo sets SUDO_UID); 0: none. */
static uint32_t sudo_uid(uid_t uid)
{
    const char *s = getenv("SUDO_UID");
    char *end;
    if (uid != 0 || s == NULL || *s < '0' || *s > '9') return 0;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    return errno == 0 && *end == '\0' && v <= 0xfffffffful ? (uint32_t)v : 0;
}

static int admin_offline(const char *config, const char *key_file, const char *db, int argc, char **argv)
{
    oc_admin_t a;
    memset(&a, 0, sizeof(a));
    /* Who asked, taken before the process may become the database's owner. */
    a.uid = (uint32_t)getuid();
    a.sudo_uid = sudo_uid(getuid());
    if (load_config(config, db) != 0 || load_key(key_file) != 0) {
        oc_sig_wipe(D.key, sizeof(D.key));
        return 1;
    }
    if (make_db_dir() != 0 || drop_to_db_owner() != 0 || open_db() != 0) {
        oc_sig_wipe(D.key, sizeof(D.key));
        return 1;
    }
    a.sql = D.sql;
    a.route = &D.route;
    a.cfg = &D.cfg;
    a.random = urandom;
    oc_buf_t out = { 0 };
    int rc = oc_admin_run(&a, argc, argv, &out);
    if (out.p != NULL) write_all(rc == 0 ? STDOUT_FILENO : STDERR_FILENO, out.p, out.n);
    oc_buf_free(&out);
    oc_sql_close(D.sql);
    return rc;
}

/* The QR code itself, if qrencode is installed and a person is looking. */
static void draw_qr(const char *text)
{
    const char *code = strstr(text, "opencell:");
    if (code == NULL || !isatty(STDOUT_FILENO) || system("command -v qrencode >/dev/null 2>&1") != 0) return;
    char line[256];
    snprintf(line, sizeof(line), "%.*s", (int)strcspn(code, "\n"), code);
    FILE *q = popen("qrencode -t ANSIUTF8", "w");
    if (q != NULL) {
        setvbuf(q, NULL, _IONBF, 0); /* no stdio buffer holding the code */
        fputs(line, q);
        pclose(q);
    }
    oc_sig_wipe(line, sizeof(line));
}

/* One request (field first unless ""), its answer written out: the
 * command's rc, 1 when there is no whole answer, or 3 - nothing written -
 * for a usage answer (2) to a request that carried the sudo field. */
static int admin_once(const char *sock, const char *field, int argc, char **argv)
{
    int fd = oc_unix_connect_wait(sock, CLIENT_WAIT_S * 1000); /* a busy daemon's full backlog is waited out */
    if (fd < 0 && errno == ETIMEDOUT) {
        fprintf(stderr, "oc-core is not accepting on %s (running but stuck?)\n", sock);
        return 1;
    }
    if (fd < 0) {
        fprintf(stderr, "oc-core is not running (%s: %s); for a stopped core: oc-core admin --offline ...\n", sock,
                strerror(errno));
        return 1;
    }
    struct timeval tv = { CLIENT_WAIT_S, 0 };
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (field[0] != '\0' && write_all(fd, field, strlen(field) + 1u) != 0) {
        fprintf(stderr, "%s: %s\n", sock, strerror(errno));
        close(fd);
        return 1;
    }
    for (int i = 0; i < argc; i++) {
        if (write_all(fd, argv[i], strlen(argv[i]) + 1u) != 0) {
            fprintf(stderr, "%s: %s\n", sock, strerror(errno));
            close(fd);
            return 1;
        }
    }
    shutdown(fd, SHUT_WR);
    oc_buf_t in = { 0 };
    char buf[4096];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0 || (r < 0 && errno == EINTR)) {
        if (r > 0) oc_buf_add(&in, buf, (size_t)r); /* bytes as they come: a NUL does not end them */
    }
    oc_sig_wipe(buf, sizeof(buf)); /* the answer may be an activation code */
    close(fd);
    /* "RC BYTES\n" then the answer: r < 0 (timed out or failed) or fewer
     * bytes than the head says, and none of it counts. */
    int rc = -1;
    size_t body = 0;
    unsigned long long want = 0;
    char *nl = in.p != NULL ? memchr(in.p, '\n', in.n < 32u ? in.n : 32u) : NULL;
    if (r == 0 && nl != NULL && nl - in.p >= 3 && in.p[0] >= '0' && in.p[0] <= '2' && in.p[1] == ' ' &&
        in.p[2] >= '0' && in.p[2] <= '9') {
        char *end;
        errno = 0;
        want = strtoull(in.p + 2, &end, 10);
        if (errno == 0 && end == nl) {
            rc = in.p[0] - '0';
            body = (size_t)(nl + 1 - in.p);
        }
    }
    if (rc < 0 || in.err) {
        fprintf(stderr, in.err ? "out of memory reading oc-core's answer\n" : "no answer from oc-core\n");
        oc_buf_free(&in);
        return 1;
    }
    if (in.n - body != want) {
        fprintf(stderr, "answer cut short (%zu of %llu bytes): try again\n", in.n - body, want);
        oc_buf_free(&in);
        return 1;
    }
    if (rc == 2 && field[0] != '\0') { /* maybe a daemon older than the field: asked again without it */
        oc_buf_free(&in);
        return 3;
    }
    write_all(rc == 0 ? STDOUT_FILENO : STDERR_FILENO, in.p + body, in.n - body);
    if (rc == 0 && argc >= 2 && strcmp(argv[0], "sub") == 0 && strcmp(argv[1], "issue") == 0) draw_qr(in.p + body);
    oc_buf_free(&in); /* wiped */
    return rc;
}

static int admin_client(const char *sock, int argc, char **argv)
{
    /* As root under sudo, the operator behind it goes first (oc_admin.h),
     * for the audit record. */
    char field[sizeof(OC_ADMIN_SUDO_FIELD) + 10];
    uint32_t su = sudo_uid(geteuid());
    field[0] = '\0';
    if (su != 0) snprintf(field, sizeof(field), OC_ADMIN_SUDO_FIELD "%u", (unsigned)su);
    size_t need = field[0] != '\0' ? strlen(field) + 1u : 0;
    for (int i = 0; i < argc; i++) need += strlen(argv[i]) + 1u;
    if (argc > ADMIN_ARGS_MAX || need > ADMIN_REQ_MAX) {
        fprintf(stderr, "a command of at most %d words and %u bytes\n", ADMIN_ARGS_MAX, ADMIN_REQ_MAX);
        return 2;
    }
    /* A daemon older than the sudo field (before it came in: v0.1.0) takes
     * it for a command and answers usage (2): the request goes again
     * without it, once. A 2 from a daemon that knows the field means the
     * command is not one: asking again costs a second usage record. */
    int rc = admin_once(sock, field, argc, argv);
    return rc == 3 ? admin_once(sock, "", argc, argv) : rc;
}

static int usage(void)
{
    fprintf(stderr, "usage: oc-core [--config FILE] [--key-file FILE] [--db PATH]\n"
                    "       oc-core admin [--socket PATH] [--config FILE] COMMAND...\n"
                    "       oc-core admin --offline [--config FILE] [--key-file FILE] [--db PATH] COMMAND...\n"
                    "       oc-core --version\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *config = DEFAULT_CONFIG, *key_file = NULL, *sock = NULL, *db = NULL;
    int admin = 0, offline = 0, i = 1;
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("oc-core %s\n", OC_VERSION);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "admin") == 0) {
        admin = 1;
        i = 2;
    }
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) config = argv[++i];
        else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) key_file = argv[++i];
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) db = argv[++i];
        else if (admin && strcmp(argv[i], "--socket") == 0 && i + 1 < argc) sock = argv[++i];
        else if (admin && strcmp(argv[i], "--offline") == 0) offline = 1;
        else return usage();
    }
    if (!admin) {
        if (i != argc) return usage();
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        no_core_dumps();
        return run_daemon(config, key_file, db);
    }
    if (i == argc) return usage();
    if (offline) {
        if (sock != NULL) return usage();
        no_core_dumps();
        return admin_offline(config, key_file, db, argc - i, argv + i);
    }
    if (key_file != NULL || db != NULL) return usage(); /* the daemon has its own */
    if (sock == NULL) {
        static oc_kv_t kv;
        sock = oc_kv_load(&kv, config) == 0 && oc_kv_get(&kv, "admin_socket") != NULL ? oc_kv_get(&kv, "admin_socket")
                                                                                      : DEFAULT_ADMIN;
    }
    return admin_client(sock, argc - i, argv + i);
}
