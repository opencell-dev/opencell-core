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
cat >"$OUT/pgbin/pg_ctl" <<'EOF'
#!/bin/bash
echo "pg_ctl $*" >>"$FAKE_CALLS"
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
    grep -q -- "--config=/etc/pgbackrest/drill.conf --stanza=oc-east --type=time --target=.* --target-action=promote" "$FAKE_CALLS"
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

[ "$fails" -eq 0 ] || { echo "$fails failed"; exit 1; }
echo "all passed"
