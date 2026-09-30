# OpenCell network core (oc-core)

The central network software of [OpenCell](https://github.com/opencell-dev/opencell): the subscriber database (HSS/AuC with MILENAGE), activation, registration, the location registry, call routing and switching between cells, and the echo service. Later, for several servers: asynchronous replication, block (NPA) transfer between tenants, and OCSS, the core-to-core signalling system.

- `oc_core/`: the core as a portable C11 library (no OS calls): the cell-core codec, HSS/AuC, registry, switch, echo service, a channel list per group of cells.
- `oc_cell/`: a cell's network side (`oc_sig_net` and the core client), which `oc-cell` in [opencell-pi](https://github.com/opencell-dev/opencell-pi) runs.
- `oc/`: the Linux side: the `oc-core` program (the daemon and `oc-core admin ...`), the SQLite store with AES-256-GCM sealed keys, and `oc_util` (config files, the framing on Unix sockets, logging), which `oc-cell` shares.
- `tools/deploy/oc-deploy`: installs a tagged revision of `oc-core` or `oc-cell` on a host over SSH (`oc-deploy deploy REPO_DIR TAG HOST`; `rollback`/`list`/`status` manage what is already there), builds it on the target, and keeps the previous build for `rollback`.
- `dist/`: the systemd unit and an example `/etc/opencell/oc-core.conf`.
- `third_party/opencell-firmware`: the firmware repository (for `oc_sig`), a submodule pinned to a commit.

Build and test (Debian 13: `cmake gcc libssl-dev libsqlite3-dev`):

~~~bash
git submodule update --init
cmake -S . -B build && cmake --build build -j && (cd build && ctest)
~~~

A new core, as root on its host after `oc-deploy` (the master key is 32 random bytes, root's and 0400, network-core spec §5; back it up offline):

~~~bash
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin oc-core
groupadd -f oc-admin; groupadd -f oc-cell
install -d -m 0755 /etc/opencell; install -d -o oc-core -g oc-core -m 0700 /var/lib/opencell/core
(umask 077; head -c 32 /dev/urandom > /etc/opencell/master.key) && chmod 0400 /etc/opencell/master.key
cp dist/oc-core.conf.example /etc/opencell/oc-core.conf
oc-core admin --offline --key-file /etc/opencell/master.key net init
oc-core admin --offline --key-file /etc/opencell/master.key cell add 1 my-cell
systemctl enable --now oc-core
oc-core admin sub add +883-1-606-555-01234 && oc-core admin sub issue +883-1-606-555-01234
~~~

Schema upgrades: the daemon migrates its database at start (`PRAGMA user_version`), after a `.backup` next to it (`core.db.v1.<time>`). Schema v2 (v0.2.0, the admin API) only adds four indexes, so rolling back to v0.1.x needs no restore and loses nothing written since: stop `oc-core`, run `sqlite3 /var/lib/opencell/core/core.db "DROP INDEX audit_number; DROP INDEX cdr_caller; DROP INDEX cdr_called; DROP INDEX token_unused_expiry; PRAGMA user_version = 1;"` (`OC_SQL_V2_TO_V1` in `oc/include/oc_sql.h`, pinned by `test_oc_sql`), then start the old build. Keep the backup for a damaged database.

The running daemon takes `oc-core admin ...` over a local Unix socket (`/run/opencell/admin.sock`, group `oc-admin`); every admin command is audited. A single site's cells connect to `/run/opencell/core.sock` (group `oc-cell`) on the same host. On the bench, the core instead runs on a separate VM: the Pi reaches it by holding a persistent SSH forward of that socket (`oc-core-link.service`, see [opencell-pi](https://github.com/opencell-dev/opencell-pi)'s README and `docs/bench/network-core-bench.md` there) — plan 9 replaces this with a TCP/TLS link the cell dials directly.

Design: `docs/superpowers/specs/2026-09-27-network-core-design.md` (§17 for these programs). Plans: `docs/superpowers/plans/2026-09-27-net-core-1-lc-core.md` (the libraries) and `docs/superpowers/plans/2026-09-28-oc-core-oc-cell-bench.md` (the programs, on the Pi bench).
