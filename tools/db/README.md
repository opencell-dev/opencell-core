# Database layer tools (postgres-ha spec, plan (a))

The PostgreSQL high-availability layer of `docs/superpowers/specs/2026-09-30-postgres-ha-design.md`:
two Patroni clusters (`oc-east` on `oc-db-1`, `oc-west` on `oc-core-2`), a three-site etcd, and a
pgBackRest repository on `oc-ldn-1` (London, Kentucky). The host configuration itself is in plan (a),
`docs/superpowers/plans/2026-09-30-postgres-a-infra.md`; the runbooks are `docs/ops/postgres-runbooks.md`
(both in the docs repository). This directory holds the scripts and units the plan installs.

| File | Installed on | What it does |
|---|---|---|
| `oc-db-check` | `oc-ldn-1` (role `witness`), `oc-db-1` (`member`), `oc-core-2` (`local`) as `/usr/local/sbin/oc-db-check` | Once a minute: Patroni, Postgres (as `oc_monitor`), a heartbeat row (as `oc_drill`), etcd, pgBackRest, the drills, WireGuard, disks, certificates. Conditions become alerts after their time (spec §14.2); mail on a change. Config `/etc/opencell/db-check.conf`, mail `/etc/opencell/alert-smtp.env`, state `/var/lib/oc-db-check/state.json`.. Each checker that writes heartbeats also watches the other's (`[check] peer_checker`: `oc-db-1` on London, `oc-ldn-1` on `oc-db-1`) and raises `checker-silent:<host>` after 10 min without a row; the member then checks the clusters itself (review final I2). `--digest` mails the daily summary. |
| `oc-db-drill` | `oc-ldn-1` | The restore drill: a stanza restored to a point in time into a scratch Postgres, checked (`pg_amcheck`, the heartbeat, the databases), deleted. Result in `/var/lib/oc-db-drill/last-<stanza>.json`.. Runbook R4a uses it too: `oc-db-drill C --target 'YYYY-MM-DD HH:MM:SS+00' --keep` leaves the restored copy running (port 5498, local socket, `/var/lib/oc-db-drill/manual-C`; no drill result written), `oc-db-drill C --cleanup` removes it (review final C1); `--repo PATH` restores from another repository path, a clone of a ZFS snapshot (runbook R4c, review final I4). |
| `oc-db-writer` | `oc-ldn-1` | The failover drill's witness: numbered rows into `oc_drill.drill_rows` through a multi-host connection, then `verify` that no committed row is missing. |
| `oc-zfs-snap` | `pvelondon` (the host, not the container) | Daily snapshots of `esas/opencell-pgbackrest`, and a monthly one whenever none exists yet for the current month (not only on the 1st: a catch-up run still gets it); keeps 30 and 6. |
| `oc-db-alert-mail` | the three hosts and `pvelondon`, as `/usr/local/sbin/oc-db-alert-mail` | The shared `OnFailure=` mailer for `oc-db-check`, `oc-zfs-snap` and `oc-etcd-defrag` (systemd itself killing/failing a run, or a unit nothing else watches): "UNIT failed on HOST: N failure(s) since …", rate-limited to at most one mail per unit per hour (a stamp in `/var/lib/oc-db-alert-mail`). Delivery: a systemd credential (`LoadCredential=smtp:/etc/opencell/alert-smtp.env`) on the three database hosts; otherwise `--env` read directly; otherwise `/usr/sbin/sendmail -t` to `root` on `pvelondon`, which carries no SMTP secret at all (spec §9.3). |
| `systemd/oc-db-check.{service,timer}` | the three hosts | every minute (the next run starts a minute after the previous one *finished*, so a slow run never overlaps the next); `TimeoutStartSec=180` (the worst-case sequential budget); `OnFailure=` the shared mailer |
| `systemd/oc-db-digest.{service,timer}` | `oc-ldn-1` | 12:00 UTC daily: `oc-db-check --digest` mails "daily: all quiet" or "daily: N alerting" with the clusters, etcd, backups, drills and the checkers' heartbeats; its absence is the dead-man's signal for London and the mail path (review final I2) |
| `systemd/oc-pgbackrest-{full,diff}@.{service,timer}` | `oc-ldn-1` | full on Sunday, differential Monday–Saturday, 02:00 UTC, per stanza |
| `systemd/oc-db-drill@.{service,timer}` | `oc-ldn-1` | the 1st of each month, 04:00 UTC, per stanza; the two stanzas' drills serialise themselves (a shared lock file) if they ever land on the same run |
| `systemd/oc-etcd-defrag.{service,timer}` | `oc-ldn-1` | the 15th of each month; `OnFailure=` the shared mailer |
| `systemd/oc-zfs-snap.{service,timer}` | `pvelondon` | daily, 04:30 UTC; after the pool is imported (`zfs-mount.service`); `OnFailure=` the shared mailer |
| `systemd/oc-db-alert-failure@.service` | the three hosts and `pvelondon`, as `/etc/systemd/system/oc-db-alert-failure@.service` | the target of the `OnFailure=` lines above: `oc-db-alert-mail %i` (the raw instance: `%I` would turn the dashes of `oc-db-check.service` into slashes), `LoadCredential=`+`DynamicUser=yes` (no root needed), `StartLimitIntervalSec=3600`/`StartLimitBurst=100` (a coarse backstop independent of the mailer's own hourly stamp) |
| `systemd/oc-db-alert-failure-pvelondon.conf` | `pvelondon` only, as `/etc/systemd/system/oc-db-alert-failure@.service.d/pvelondon.conf` | drops `LoadCredential=`/`DynamicUser=` and runs as `root` instead: there is no SMTP secret to load on this host, so `oc-db-alert-mail` falls back to local mail, and plan (a) does not know this host's MTA well enough to sandbox it further |
| `systemd/patroni-opencell.conf` | `oc-db-1`, `oc-core-2` as `/etc/systemd/system/patroni@.service.d/opencell.conf` | after `wg0` and etcd; restart on failure after 2 s (a killed Patroni must reopen its watchdog within about 25 s: review final m7) |
| `systemd/after-wg.conf` | as `etcd.service.d/opencell.conf` and `pgbackrest.service.d/opencell.conf` | after `wg0`; restart on failure after 5 s (Debian's etcd unit only restarts on-abnormal: review final m9) |

**Before trusting `pvelondon`'s alerts:** this host has no SMTP secret (spec §9.3 places
`alert-smtp.env` only on `oc-ldn-1`, `oc-db-1` and `oc-core-2`), so `oc-db-alert-mail` there always
falls back to the local mail path (`/usr/sbin/sendmail -t` addressed to `root`). **The user must
have Proxmox's own root-mail forwarding already configured on `pvelondon`** (Datacenter →
Notifications, or `/etc/pve/notifications.cfg`) for that mail to go anywhere; plan (a) Task 14's
snapshot-timer step (the user's go-ahead step) carries this as an open item to confirm before
relying on `oc-zfs-snap`'s failure alerts from this host.

Tests (no server needed): `python3 tests/test_oc_db_check.py tools/db/oc-db-check`,
`bash tests/test_oc_db_tools.sh tools/db OUT` and `python3 tests/test_oc_db_alert_mail.py
tools/db/oc-db-alert-mail`, all also under `ctest`.
