# Database layer tools (postgres-ha spec, plan (a))

The PostgreSQL high-availability layer of `docs/superpowers/specs/2026-09-30-postgres-ha-design.md`:
two Patroni clusters (`oc-east` on `oc-db-1`, `oc-west` on `oc-core-2`), a three-site etcd, and a
pgBackRest repository on `oc-ldn-1` (London, Kentucky). The host configuration itself is in plan (a),
`docs/superpowers/plans/2026-09-30-postgres-a-infra.md`; the runbooks are `docs/ops/postgres-runbooks.md`
(both in the docs repository). This directory holds the scripts and units the plan installs.

| File | Installed on | What it does |
|---|---|---|
| `oc-db-check` | `oc-ldn-1` (role `witness`), `oc-db-1` (`member`), `oc-core-2` (`local`) as `/usr/local/sbin/oc-db-check` | Once a minute: Patroni, Postgres (as `oc_monitor`), a heartbeat row (as `oc_drill`), etcd, pgBackRest, the drills, WireGuard, disks, certificates. Conditions become alerts after their time (spec §14.2); mail on a change. Config `/etc/opencell/db-check.conf`, mail `/etc/opencell/alert-smtp.env`, state `/var/lib/oc-db-check/state.json`. |
| `oc-db-drill` | `oc-ldn-1` | The restore drill: a stanza restored to a point in time into a scratch Postgres, checked (`pg_amcheck`, the heartbeat, the databases), deleted. Result in `/var/lib/oc-db-drill/last-<stanza>.json`. |
| `oc-db-writer` | `oc-ldn-1` | The failover drill's witness: numbered rows into `oc_drill.drill_rows` through a multi-host connection, then `verify` that no committed row is missing. |
| `oc-zfs-snap` | `pvelondon` (the host, not the container) | Daily snapshots of `esas/opencell-pgbackrest`, and a monthly one whenever none exists yet for the current month (not only on the 1st: a catch-up run still gets it); keeps 30 and 6. |
| `oc-db-alert-mail` | the three hosts, as `/usr/local/sbin/oc-db-alert-mail` | The shared `OnFailure=` mailer for `oc-db-check`, `oc-zfs-snap` and `oc-etcd-defrag` (systemd itself killing/failing a run, or a unit nothing else watches): "UNIT failed on HOST", same `/etc/opencell/alert-smtp.env` as `oc-db-check`'s own alerts. |
| `systemd/oc-db-check.{service,timer}` | the three hosts | every minute (the next run starts a minute after the previous one *finished*, so a slow run never overlaps the next); `TimeoutStartSec=180` (the worst-case sequential budget); `OnFailure=` the shared mailer |
| `systemd/oc-pgbackrest-{full,diff}@.{service,timer}` | `oc-ldn-1` | full on Sunday, differential Monday–Saturday, 02:00 UTC, per stanza |
| `systemd/oc-db-drill@.{service,timer}` | `oc-ldn-1` | the 1st of each month, 04:00 UTC, per stanza; the two stanzas' drills serialise themselves (a shared lock file) if they ever land on the same run |
| `systemd/oc-etcd-defrag.{service,timer}` | `oc-ldn-1` | the 15th of each month; `OnFailure=` the shared mailer |
| `systemd/oc-zfs-snap.{service,timer}` | `pvelondon` | daily, 04:30 UTC; after the pool is imported (`zfs-mount.service`); `OnFailure=` the shared mailer |
| `systemd/oc-db-alert-failure@.service` | the three hosts and `pvelondon`, as `/etc/systemd/system/oc-db-alert-failure@.service` | the target of the `OnFailure=` lines above: `oc-db-alert-mail %I` |
| `systemd/patroni-opencell.conf` | `oc-db-1`, `oc-core-2` as `/etc/systemd/system/patroni@.service.d/opencell.conf` | after `wg0` and etcd; restart on failure |
| `systemd/after-wg.conf` | as `etcd.service.d/opencell.conf` and `pgbackrest.service.d/opencell.conf` | after `wg0` |

Tests (no server needed): `python3 tests/test_oc_db_check.py tools/db/oc-db-check` and
`bash tests/test_oc_db_tools.sh tools/db OUT`, both also under `ctest`.
