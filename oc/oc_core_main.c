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
 * connection: the client sends its words, each ending in a NUL, and shuts
 * its side; the daemon answers "<status>\n" and the command's output. The
 * master key comes from --key-file or the systemd credential master.key
 * ($CREDENTIALS_DIRECTORY). Logs go to stderr with journald priorities.
 *
 * Links: the daemon closes a link oc_core drops (io.close); a link whose
 * peer vanished, or whose send or read failed, is marked dead and oc_core
 * hears of it (oc_core_link_down) once the call in progress has returned.
 * Reconnect backoff is the cell's business (oc_core.h, oc_core_tick): no
 * state here outlives a link. */
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
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "oc_admin.h"
#include "oc_conn.h"
#include "oc_core.h"
#include "oc_kv.h"
#include "oc_log.h"
#include "oc_seal.h"
#include "oc_sig_keys.h"
#include "oc_sql.h"

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
} D = { .cell_l = -1, .admin_l = -1 };

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

/* ---- configuration ---- */

static const char *const KEYS[] = { "core_id", "key_id", "echo", "block", "db", "cell_socket", "cell_group",
                                    "admin_socket", "admin_group", NULL };

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
        unsigned idx;
        const char *b = oc_kv_nth(&D.kv, "block", i);
        if (sscanf(b, "%31s %u %c", prefix, &idx, &extra) != 2 || idx > 65535 ||
            oc_core_route_add(&D.route, prefix, (uint16_t)idx, D.cfg.core_id) != 0) {
            oc_log(OC_LOG_ERR, "config: block = '%s': PREFIX INDEX, e.g. 8831606 1 (a new prefix and index)", b);
            return -1;
        }
    }
    if (D.route.n == 0) {
        oc_log(OC_LOG_ERR, "config: no block: add e.g. block = 8831606 1");
        return -1;
    }
    D.db = db != NULL ? db : oc_kv_get(&D.kv, "db") ? oc_kv_get(&D.kv, "db") : "/var/lib/opencell/core/core.db";
    D.cell_sock = oc_kv_get(&D.kv, "cell_socket") ? oc_kv_get(&D.kv, "cell_socket") : "/run/opencell/core.sock";
    D.admin_sock = oc_kv_get(&D.kv, "admin_socket") ? oc_kv_get(&D.kv, "admin_socket") : DEFAULT_ADMIN;
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

/* Waits for fd to be ready for ev: 1, or 0 at the deadline (mono_us) or
 * once SIGTERM has come (the poll is interrupted, and the stop wins). */
static int admin_wait(int fd, short ev, uint64_t deadline)
{
    for (;;) {
        uint64_t now = mono_us();
        if (g_stop || now >= deadline) return 0;
        struct pollfd p = { fd, ev, 0 };
        int r = poll(&p, 1, (int)((deadline - now + 999u) / 1000u));
        if (r > 0) return 1;
        if (r < 0 && errno != EINTR) return 0;
    }
}

/* All of p to the admin peer before the deadline: 0 or -1. */
static int admin_send(int fd, const char *p, size_t n, uint64_t deadline)
{
    while (n > 0) {
        if (!admin_wait(fd, POLLOUT, deadline)) return -1;
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
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
        if (!admin_wait(fd, POLLIN, deadline)) {
            /* Too slow, or oc-core is stopping: dropped unanswered, nothing run. */
            if (!g_stop) oc_log(OC_LOG_WARNING, "admin (uid %u): the request took more than %d s: dropped",
                               (unsigned)cr.uid, ADMIN_IO_S);
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
    char *argv[ADMIN_ARGS_MAX];
    int argc = 0;
    for (size_t i = 0; !cut && i < n; i += strlen(req + i) + 1u) {
        if (argc == ADMIN_ARGS_MAX || memchr(req + i, '\0', n - i) == NULL) {
            cut = 1; /* too many words, or the last without its NUL */
            break;
        }
        argv[argc++] = req + i;
    }
    oc_buf_t out = { 0 };
    if (cut) {
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
        rc = oc_admin_run(&a, argc, argv, &out); /* audited there, the words cleaned */
        snprintf(what, sizeof(what), "%s%s", argc > 0 ? argv[0] : "", argc > 1 ? " ..." : "");
    }
    oc_log_clean(what); /* the peer's words: no line of their own in the journal */
    oc_log(OC_LOG_INFO, "admin (uid %u): %s -> %d%s", (unsigned)cr.uid, what, rc, out.err ? " (output cut)" : "");
    char head[8];
    int hn = snprintf(head, sizeof(head), "%d\n", rc);
    /* rc is 1 when the output could not be made whole (oc_admin.h): what
     * there is goes out, marked failed. */
    deadline = mono_us() + ADMIN_IO_S * 1000000ull; /* the answer's own budget */
    if (admin_send(fd, head, (size_t)hn, deadline) != 0 ||
        (out.p != NULL && admin_send(fd, out.p, out.n, deadline) != 0)) {
        oc_log(OC_LOG_WARNING, "admin (uid %u): the answer was not taken within %d s: dropped", (unsigned)cr.uid,
               ADMIN_IO_S);
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
    oc_log(OC_LOG_NOTICE, "oc-core %s: core %u, key %u, %u blocks, db %s (v%d), cells on %s, admin on %s", OC_VERSION,
           D.cfg.core_id, D.cfg.key_id, D.route.n, D.db, oc_sql_version(D.sql), D.cell_sock, D.admin_sock);
    while (!g_stop) {
        struct pollfd p[2 + OC_CORE_LINKS];
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
        int r = poll(p, np, 100); /* oc_core_tick at least every 100 ms (CELL_CFG retries, PING, timers) */
        if (r < 0 && errno != EINTR) {
            oc_log(OC_LOG_ERR, "poll: %s", strerror(errno));
            break;
        }
        if (r > 0) {
            if (p[0].revents & POLLIN) accept_cell();
            if (p[1].revents & POLLIN) serve_admin();
            for (nfds_t i = 2; i < np; i++) {
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
        oc_core_tick(&D.core, mono_us());
        for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
            if (D.link[i].used && D.link[i].dead) link_lost(&D.link[i]);
        }
    }
    oc_log(OC_LOG_NOTICE, "oc-core: stopping");
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
    return 0;
}

/* First setup on a fresh machine: the database's directory (the unit's
 * StateDirectory, which systemd makes only when the unit first starts) is
 * made if missing - 0700, and as root owned by DAEMON_USER, as systemd
 * would make it; missing parents 0755. An existing directory is left as it
 * is. 0 or -1. */
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
    for (char *p = dir + 1; *p != '\0'; p++) { /* the parents */
        if (*p != '/') continue;
        *p = '\0';
        int r = mkdir(dir, 0755);
        *p = '/';
        if (r != 0 && errno != EEXIST) {
            oc_log(OC_LOG_ERR, "%.*s: %s", (int)(p - dir), dir, strerror(errno));
            return -1;
        }
    }
    if (mkdir(dir, 0700) != 0 || chmod(dir, 0700) != 0) {
        oc_log(OC_LOG_ERR, "%s: %s", dir, strerror(errno));
        return -1;
    }
    if (geteuid() == 0) {
        struct passwd *pw = getpwnam(DAEMON_USER);
        if (pw == NULL) {
            oc_log(OC_LOG_WARNING, "%s made, root's: there is no user %s to give it to", dir, DAEMON_USER);
        } else if (chown(dir, pw->pw_uid, pw->pw_gid) != 0) {
            oc_log(OC_LOG_ERR, "%s: can't give it to %s: %s", dir, DAEMON_USER, strerror(errno));
            return -1;
        }
    }
    oc_log(OC_LOG_NOTICE, "%s made (0700)", dir);
    return 0;
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

static int admin_client(const char *sock, int argc, char **argv)
{
    size_t need = 0;
    for (int i = 0; i < argc; i++) need += strlen(argv[i]) + 1u;
    if (argc > ADMIN_ARGS_MAX || need > ADMIN_REQ_MAX) {
        fprintf(stderr, "a command of at most %d words and %u bytes\n", ADMIN_ARGS_MAX, ADMIN_REQ_MAX);
        return 2;
    }
    int fd = oc_unix_connect(sock);
    if (fd < 0) {
        fprintf(stderr, "oc-core is not running (%s: %s); for a stopped core: oc-core admin --offline ...\n", sock,
                strerror(errno));
        return 1;
    }
    struct timeval tv = { CLIENT_WAIT_S, 0 };
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
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
    /* r < 0: timed out or failed - what came may be cut, so none of it counts */
    int rc = r == 0 && in.n >= 2 && in.p[1] == '\n' && in.p[0] >= '0' && in.p[0] <= '2' ? in.p[0] - '0' : -1;
    if (rc < 0 || in.err) {
        fprintf(stderr, in.err ? "out of memory reading oc-core's answer\n" : "no answer from oc-core\n");
        oc_buf_free(&in);
        return 1;
    }
    write_all(rc == 0 ? STDOUT_FILENO : STDERR_FILENO, in.p + 2, in.n - 2u);
    if (rc == 0 && argc >= 2 && strcmp(argv[0], "sub") == 0 && strcmp(argv[1], "issue") == 0) draw_qr(in.p + 2);
    oc_buf_free(&in); /* wiped */
    return rc;
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
        return run_daemon(config, key_file, db);
    }
    if (i == argc) return usage();
    if (offline) {
        if (sock != NULL) return usage();
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
