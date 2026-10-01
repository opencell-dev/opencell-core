#!/bin/bash
# tools/db/oc-zfs-snap, oc-db-drill and oc-db-writer against fake zfs,
# pgbackrest, pg_ctl, psql and pg_amcheck: what they create, destroy, report
# and clean up.
# usage: test_oc_db_tools.sh TOOLS_DB_DIR OUT
set -uo pipefail
TOOLS=$1
OUT=$2
fails=0
ok() { echo "ok - $*"; }
bad() { echo "FAIL - $*"; fails=$((fails + 1)); }
expect() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
rm -rf "$OUT"
mkdir -p "$OUT/bin"

# ---- oc-zfs-snap -------------------------------------------------------------
cat >"$OUT/bin/zfs" <<'EOF'
#!/bin/bash
# fake zfs: snapshots of one dataset in $FAKE_ZFS (one name per line, oldest first)
echo "$*" >>"$FAKE_ZFS.calls"
case "$1 $2 $3" in
    "list -H -o") echo "$5" ;;
    "list -H -t") sed "s|^|${*: -1}@|" "$FAKE_ZFS" ;;
    snapshot*) echo "${2#*@}" >>"$FAKE_ZFS" ;;
    destroy*) grep -vx "${2#*@}" "$FAKE_ZFS" >"$FAKE_ZFS.tmp"; mv "$FAKE_ZFS.tmp" "$FAKE_ZFS" ;;
esac
EOF
chmod +x "$OUT/bin/zfs"
export OC_ZFS=$OUT/bin/zfs FAKE_ZFS=$OUT/snaps
snap() { OC_TODAY=$1 "$TOOLS/oc-zfs-snap" esas/opencell-pgbackrest "${@:2}" >"$OUT/snap.out" 2>&1; }

: >"$FAKE_ZFS"; : >"$FAKE_ZFS.calls"
snap 20261001
expect "the 1st of a month: a daily and a monthly snapshot" \
    grep -qx "snapshot esas/opencell-pgbackrest@oc-daily-20261001" "$FAKE_ZFS.calls"
expect "...the monthly one" grep -qx "snapshot esas/opencell-pgbackrest@oc-monthly-202610" "$FAKE_ZFS.calls"
: >"$FAKE_ZFS.calls"
snap 20261001
expect "run twice the same day: nothing new" bash -c "! grep -q '^snapshot' '$FAKE_ZFS.calls'"

: >"$FAKE_ZFS"; : >"$FAKE_ZFS.calls"
for d in $(seq 1 31); do printf 'oc-daily-202608%02d\n' "$d"; done >>"$FAKE_ZFS"
echo oc-daily-20260901 >>"$FAKE_ZFS" # 32 dailies, oldest first
printf 'manual-before-upgrade\noc-daily-old\n' >>"$FAKE_ZFS"
snap 20260915
expect "33 dailies: the 3 oldest go" bash -c "[ \$(grep -c '^destroy' '$FAKE_ZFS.calls') = 3 ] && grep -qx 'destroy esas/opencell-pgbackrest@oc-daily-20260801' '$FAKE_ZFS.calls' && grep -qx 'destroy esas/opencell-pgbackrest@oc-daily-20260803' '$FAKE_ZFS.calls'"
expect "30 dailies remain, today's among them" bash -c "[ \$(grep -c '^oc-daily-[0-9]*$' '$FAKE_ZFS') = 30 ] && grep -qx oc-daily-20260915 '$FAKE_ZFS'"
expect "other snapshots are never destroyed" bash -c "grep -qx manual-before-upgrade '$FAKE_ZFS' && grep -qx oc-daily-old '$FAKE_ZFS'"
expect "only single snapshots are destroyed (never -r)" bash -c "! grep -qE 'destroy .*-r|destroy esas/opencell-pgbackrest\$' '$FAKE_ZFS.calls'"

: >"$FAKE_ZFS"; for m in 01 02 03 04 05 06 07 08; do echo "oc-monthly-2026$m" >>"$FAKE_ZFS"; done; : >"$FAKE_ZFS.calls"
snap 20260901
expect "9 monthlies: the 3 oldest go, 6 remain" bash -c "[ \$(grep -c '^oc-monthly-' '$FAKE_ZFS') = 6 ] && ! grep -q oc-monthly-202603 '$FAKE_ZFS' && grep -q oc-monthly-202609 '$FAKE_ZFS'"

# M1: a host down over the 1st's run must still get that month's snapshot
# once it catches up, not only exactly on the 1st -- and not a second time
# once it has one.
: >"$FAKE_ZFS"; : >"$FAKE_ZFS.calls"
snap 20261002
expect "catch-up on the 2nd still takes the month's snapshot" \
    grep -qx "snapshot esas/opencell-pgbackrest@oc-monthly-202610" "$FAKE_ZFS.calls"
: >"$FAKE_ZFS.calls"
snap 20261003
expect "...but only once for the month" bash -c "! grep -q oc-monthly- '$FAKE_ZFS.calls'"

: >"$FAKE_ZFS"; : >"$FAKE_ZFS.calls"
snap 20261002 --dry-run
expect "--dry-run changes nothing" bash -c "! grep -qE '^(snapshot|destroy)' '$FAKE_ZFS.calls' && grep -q 'would run: zfs snapshot' '$OUT/snap.out'"
OC_TODAY=20261002 "$TOOLS/oc-zfs-snap" esas >/dev/null 2>&1
expect "a pool's root dataset is refused" test $? = 2

# ---- oc-db-drill -------------------------------------------------------------
mkdir -p "$OUT/pgbin"
cat >"$OUT/bin/pgbackrest" <<'EOF'
#!/bin/bash
echo "pgbackrest $*" >>"$FAKE_CALLS"
[ "${FAKE_RESTORE_RC:-0}" = 0 ] || { echo "P00  ERROR: [075]: no backup set found to restore"; exit 75; }
EOF
# I3: pg_ctl start takes out a lock (shared across stanzas, like a real
# postmaster's one scratch port/socket would collide) and holds it for
# FAKE_DRILL_DELAY; a second "start" while it is held fails, the way a real
# postmaster refuses to bind an address already in use.
cat >"$OUT/pgbin/pg_ctl" <<'EOF'
#!/bin/bash
echo "pg_ctl $*" >>"$FAKE_CALLS"
lock=${FAKE_PORTLOCK:-}
case " $* " in
    *" start "*)
        if [ -n "$lock" ]; then
            if [ -e "$lock" ]; then
                echo "pg_ctl: another postmaster might be running; lock file \"$lock\" exists" >&2
                exit 1
            fi
            : >"$lock"
        fi
        sleep "${FAKE_DRILL_DELAY:-0}"
        ;;
    *" stop "*)
        [ -z "$lock" ] || rm -f "$lock"
        ;;
esac
EOF
cat >"$OUT/pgbin/pg_amcheck" <<'EOF'
#!/bin/bash
echo "pg_amcheck $*" >>"$FAKE_CALLS"
EOF
cat >"$OUT/pgbin/psql" <<'EOF'
#!/bin/bash
sqltext=${*: -1}
case $sqltext in
    *pg_is_in_recovery*) echo f ;;
    *pg_database*) db=$(sed -n "s/.*datname = '\([a-z_0-9]*\)'.*/\1/p" <<<"$sqltext"); [ "$db" = "${FAKE_MISSING_DB:-}" ] && echo 0 || echo 1 ;;
    *heartbeat*) echo "$FAKE_HB" ;;
esac
EOF
chmod +x "$OUT/bin/pgbackrest" "$OUT/pgbin/"*
export PATH=$OUT/bin:$PATH OC_PG_BIN=$OUT/pgbin OC_DRILL_RUNAS= OC_DRILL_DIR=$OUT/drill OC_DRILL_SOCK=$OUT/sock \
    OC_DRILL_CONF=/etc/pgbackrest/drill.conf FAKE_CALLS=$OUT/drill.calls
drill() { : >"$FAKE_CALLS"; "$TOOLS/oc-db-drill" "$@" >"$OUT/drill.out" 2>&1; echo $? >"$OUT/drill.rc"; }
field() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$OUT/drill/last-oc-east.json" "$1"; }

FAKE_HB=$(($(date +%s) - 3600 - 60)) drill oc-east
expect "a good restore passes (exit 0)" test "$(cat "$OUT/drill.rc")" = 0
expect "...and says so in last-oc-east.json" test "$(field result)" = pass
expect "...with last_pass set" test "$(field last_pass)" = "$(field at)"
expect "it restored to a time with the drill config and promotes" \
    grep -q -- "--config=/etc/pgbackrest/drill.conf --config-include-path=/etc/pgbackrest/conf.d --stanza=oc-east --pg1-path=$OUT/drill/oc-east --type=time --target=.* --target-action=promote" "$FAKE_CALLS"
# With an explicit --config, pgBackRest skips its default include directory,
# where the repository's passphrase lives (conf.d/cipher.conf): both the
# restore and the restore_command it writes must name it (found on oc-ldn-1,
# 2026-09-30: "restore command requires option: repo1-cipher-pass").
expect "the restore reads the passphrase's include directory" \
    grep -q -- "^pgbackrest --config=/etc/pgbackrest/drill.conf --config-include-path=/etc/pgbackrest/conf.d --stanza=oc-east --pg1-path=" "$FAKE_CALLS"
expect "...and so does the restore_command it writes" \
    grep -q -- "restore_command=pgbackrest --config=/etc/pgbackrest/drill.conf --config-include-path=/etc/pgbackrest/conf.d --stanza=oc-east archive-get" "$FAKE_CALLS"
expect "it started the copy off the network, without a sync standby" \
    grep -q -- "listen_addresses='' .*synchronous_standby_names=" "$FAKE_CALLS"
expect "it stopped the copy and deleted it" bash -c "grep -q 'pg_ctl -D $OUT/drill/oc-east -m fast' '$FAKE_CALLS' && [ ! -e '$OUT/drill/oc-east' ]"
expect "pg_amcheck ran on every database" grep -q "pg_amcheck .*--all --install-missing" "$FAKE_CALLS"
pass_at=$(field last_pass)

FAKE_HB=$(($(date +%s) - 3600 - 900)) drill oc-east
expect "a heartbeat 15 min before the target fails (exit 1)" test "$(cat "$OUT/drill.rc")" = 1
expect "...with the reason" bash -c "grep -q 'not within 3 min before the target' '$OUT/drill.out'"
expect "...keeping the last pass" test "$(field last_pass)" = "$pass_at"
expect "...and still stops and deletes the copy" bash -c "grep -q 'pg_ctl -D .* stop' '$FAKE_CALLS' && [ ! -e '$OUT/drill/oc-east' ]"

FAKE_HB=$(($(date +%s) - 3600 + 60)) drill oc-east
expect "a heartbeat after the target fails (the restore went too far)" test "$(cat "$OUT/drill.rc")" = 1

FAKE_HB=$(($(date +%s) - 3600 - 60)) FAKE_MISSING_DB=oc_core1 drill oc-east
expect "a missing database fails" bash -c "[ \$(cat '$OUT/drill.rc') = 1 ] && grep -q 'database oc_core1 is missing' '$OUT/drill.out'"

FAKE_RESTORE_RC=1 FAKE_HB=0 drill oc-east
expect "a failed restore fails, without starting anything" \
    bash -c "[ \$(cat '$OUT/drill.rc') = 1 ] && grep -q 'pgbackrest restore failed' '$OUT/drill.out' && ! grep -q 'pg_ctl' '$FAKE_CALLS'"

drill oc-north
expect "an unknown stanza is a usage error" test "$(cat "$OUT/drill.rc")" = 2

# ---- oc-db-drill --keep / --cleanup: runbook R4a (review final C1) ------------
# R4a restores to a chosen moment and leaves the copy running to look at; it
# must use the drill's own pgBackRest call (include path, --pg1-path guard), so
# the runbook and the drill cannot drift apart again.
before=$(cat "$OUT/drill/last-oc-east.json")
drill oc-east --target '2026-10-01 01:23:45+00' --keep
expect "--keep restores and leaves the copy running (exit 0)" test "$(cat "$OUT/drill.rc")" = 0
expect "...to the given moment, into its own directory, with the include path" \
    grep -q -- "^pgbackrest --config=/etc/pgbackrest/drill.conf --config-include-path=/etc/pgbackrest/conf.d --stanza=oc-east --pg1-path=$OUT/drill/manual-oc-east --type=time --target=2026-10-01 01:23:45+00 --target-action=promote" "$FAKE_CALLS"
expect "...started on its own port, off the network" grep -q -- "pg_ctl -D $OUT/drill/manual-oc-east .*port=5498 -c listen_addresses=''.*cluster_name=manual-oc-east" "$FAKE_CALLS"
expect "...not stopped, not deleted" bash -c "! grep -q 'pg_ctl -D .* stop' '$FAKE_CALLS' && [ -d '$OUT/drill/manual-oc-east' ]"
expect "...and it is not a drill: last-oc-east.json unchanged" test "$(cat "$OUT/drill/last-oc-east.json")" = "$before"
expect "...says how to connect and how to clean up" bash -c "grep -q 'port 5498' '$OUT/drill.out' && grep -q -- '--cleanup' '$OUT/drill.out'"
drill oc-east --target '2026-10-01 01:23:45+00' --keep
expect "a second --keep never overwrites a kept copy" bash -c "[ \$(cat '$OUT/drill.rc') = 1 ] && grep -q -- '--cleanup' '$OUT/drill.out' && ! grep -q '^pgbackrest' '$FAKE_CALLS'"
drill oc-east --cleanup
expect "--cleanup stops and deletes the kept copy" bash -c "[ \$(cat '$OUT/drill.rc') = 0 ] && grep -q 'pg_ctl -D $OUT/drill/manual-oc-east -m fast' '$FAKE_CALLS' && [ ! -e '$OUT/drill/manual-oc-east' ]"
drill oc-east --target 'yesterday-ish'
expect "an unreadable --target is a usage error" test "$(cat "$OUT/drill.rc")" = 2
FAKE_RESTORE_RC=1 drill oc-east --target '2026-10-01 01:23:45+00' --keep
expect "a failed --keep restore leaves nothing behind and no drill result" \
    bash -c "[ \$(cat '$OUT/drill.rc') = 1 ] && [ ! -e '$OUT/drill/manual-oc-east' ] && [ \"\$(cat '$OUT/drill/last-oc-east.json')\" = '$before' ]"

# ---- oc-db-drill: two stanzas' drills never collide (I3) ---------------------
: >"$FAKE_CALLS"
export FAKE_PORTLOCK=$OUT/portlock FAKE_DRILL_DELAY=0.3
FAKE_HB=$(($(date +%s) - 3600 - 60)) "$TOOLS/oc-db-drill" oc-east >"$OUT/east.out" 2>"$OUT/east.err" &
p1=$!
FAKE_HB=$(($(date +%s) - 3600 - 60)) "$TOOLS/oc-db-drill" oc-west >"$OUT/west.out" 2>"$OUT/west.err" &
p2=$!
rc1=0; rc2=0
wait "$p1" || rc1=$?
wait "$p2" || rc2=$?
expect "two concurrent drills: oc-east passes (no port/socket collision)" test "$rc1" = 0
expect "...oc-west passes too" test "$rc2" = 0
expect "...both actually reached PASS (not just a nonzero rc by luck)" \
    bash -c "grep -q 'oc-db-drill oc-east: PASS' '$OUT/east.out' && grep -q 'oc-db-drill oc-west: PASS' '$OUT/west.out'"
unset FAKE_PORTLOCK FAKE_DRILL_DELAY

# ---- oc-db-writer -------------------------------------------------------------
cat >"$OUT/bin/fakepsql" <<'EOF'
#!/bin/bash
sqltext=${*: -1}
case $sqltext in
    *"max(id)"*) echo 10 ;;
    *INSERT*) id=$(sed -n 's/.*VALUES (\([0-9]*\)).*/\1/p' <<<"$sqltext")
        [ "$id" = 12 ] && { echo "connection to server was lost" >&2; exit 2; }
        exit 0 ;;
    *unnest*) echo "${FAKE_MISSING:-0}" ;;
esac
EOF
chmod +x "$OUT/bin/fakepsql"
export PSQL=$OUT/bin/fakepsql
rm -f "$OUT/w.log"
"$TOOLS/oc-db-writer" write "host=a,b" "$OUT/w.log" --every 0 --count 3 >"$OUT/w.out" 2>&1
expect "the writer starts after the highest id and logs only committed ids" test "$(paste -sd, "$OUT/w.log")" = "11,13,14"
expect "...and reports the one that failed" grep -q "id 12 not committed: connection to server was lost" "$OUT/w.out"
"$TOOLS/oc-db-writer" verify "host=a,b" "$OUT/w.log" >"$OUT/v.out"
expect "verify: nothing missing is a pass" bash -c "[ $? = 0 ] && grep -qx '3 committed, 0 missing' '$OUT/v.out'"
FAKE_MISSING=1 "$TOOLS/oc-db-writer" verify "host=a,b" "$OUT/w.log" >"$OUT/v.out"
expect "verify: a missing committed row is a failure" test $? = 1
unset PSQL

# ---- units (review final I2, m7, m9) ------------------------------------------
U=$TOOLS/systemd
expect "the daily digest runs oc-db-check --digest" grep -qx 'ExecStart=/usr/local/sbin/oc-db-check --digest' "$U/oc-db-digest.service"
expect "...at 12:00 UTC, caught up after downtime" bash -c "grep -qx 'OnCalendar=\*-\*-\* 12:00:00 UTC' '$U/oc-db-digest.timer' && grep -qx 'Persistent=true' '$U/oc-db-digest.timer'"
expect "...and a failed digest is mailed by the OnFailure mailer" grep -qx 'OnFailure=oc-db-alert-failure@%n.service' "$U/oc-db-digest.service"
# m7: a killed Patroni that holds the watchdog must be back well inside its 25 s
expect "Patroni restarts within 2 s" grep -qx 'RestartSec=2s' "$U/patroni-opencell.conf"
# m9: Debian's etcd unit restarts only on-abnormal; a bind failure (wg0 late) must retry
expect "etcd and the pgBackRest server restart on failure" bash -c "grep -qx 'Restart=on-failure' '$U/after-wg.conf' && grep -qx 'RestartSec=5s' '$U/after-wg.conf'"

[ "$fails" -eq 0 ] || { echo "$fails failed"; exit 1; }
echo "all passed"
