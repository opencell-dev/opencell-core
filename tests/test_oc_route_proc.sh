#!/bin/bash
# The signed routing table in two oc-core processes (OCSS spec 2026-11-01
# §3.6, §5): both load the same root table (made by oc-route), link over
# OCSS, report it (route.status, admin status), take a delegate addition
# over the admin API (route.offer), keep it over a restart, refuse a bad
# one, and refuse configs that can't work.
#   test_oc_route_proc.sh OC_CORE OC_ROUTE TOOL_OC_API PKI
set -u
OC=$1
ROUTE=$2
API=$3
PKI=$4
T=$(mktemp -d /tmp/oc_route_proc_XXXXXX) || exit 1
P1= P2=
cleanup() {
    [ -n "$P1" ] && kill "$P1" 2>/dev/null && wait "$P1" 2>/dev/null
    [ -n "$P2" ] && kill "$P2" 2>/dev/null && wait "$P2" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; for n in 1 2; do echo "--- core $n log"; cat "$T/log$n" 2>/dev/null; done; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
PORT=$((20000 + RANDOM % 20000))
API1=$((PORT + 1)) API2=$((PORT + 2))
FPR1=$(cat "$PKI/core.fpr")
FPR2=$(cat "$PKI/core2.fpr")
for n in 1 2; do head -c 32 /dev/urandom >"$T/key$n" && chmod 0400 "$T/key$n"; done

ROOT=$("$ROUTE" keygen "$T/root.key") || fail "keygen"
DEL=$("$ROUTE" keygen "$T/del.key") || fail "keygen"
printf '606,US-KY\n503,US-OR\n865,US-TN\n212,US-NY\n415,US-CA\n' >"$T/npa.csv"
"$ROUTE" make "$T/root.key" "$T/route.tbl" --version 1 --npa "$T/npa.csv" --core 1=oc-core-1 --core 2=oc-core-2 \
    --east 1 --west 2 --pin 606=1 --pin 503=2 --pin 865=3 --delegate "$DEL" >/dev/null || fail "make"

for n in 1 2; do
    cat >"$T/core$n.conf" <<EOF2
core_id = $n
key_id = $n
echo = $([ $n = 1 ] && echo +883160655500100 || echo +883150355500100)
route_root = $ROOT
route_table = $T/route.tbl
db = $T/core$n.db
cell_socket = $T/core$n.sock
admin_socket = $T/admin$n.sock
api_listen = 127.0.0.1:$([ $n = 1 ] && echo $API1 || echo $API2)
api_cert = $PKI/$([ $n = 1 ] && echo core || echo core2).crt
api_key = $PKI/$([ $n = 1 ] && echo core || echo core2).key
api_ca = $PKI/ca.crt
api_portal_fpr = $(cat "$PKI/portal.fpr")
api_rate = route.offer 3600 50
ocss_cert = $PKI/$([ $n = 1 ] && echo core || echo core2).crt
ocss_key = $PKI/$([ $n = 1 ] && echo core || echo core2).key
ocss_ca = $PKI/ca.crt
EOF2
done
echo "peer = 2 127.0.0.1:$PORT $FPR2" >>"$T/core1.conf"
printf 'peer = 1 - %s\nocss_listen = 127.0.0.1:%s\n' "$FPR1" "$PORT" >>"$T/core2.conf"

refused() { # WHAT SED-EXPR MESSAGE
    sed "$2" "$T/core1.conf" >"$T/bad.conf"
    out=$(timeout 5 "$OC" --config "$T/bad.conf" --key-file "$T/key1" 2>&1); rc=$?
    [ "$rc" = 1 ] || fail "$1: exit $rc ($out)"
    expect "$out" "$3"
}
refused "block lines beside route_table" '$a block = 8831606 1' "block lines and route_table: one or the other"
refused "route_table without route_root" '/^route_root/d' "route_table and route_root go together"
refused "the wrong root key" "s/^route_root = .*/route_root = $DEL/" "does not verify with route_root"
refused "a peer not in the directory" "\$a peer = 3 127.0.0.1:1 $FPR1" "peer 3 is not in the signed table's directory"

A1=("$OC" admin --offline --config "$T/core1.conf" --key-file "$T/key1")
A2=("$OC" admin --offline --config "$T/core2.conf" --key-file "$T/key2")
out=$("${A1[@]}" net init 2>&1) || fail "core 1 net init: $out"
out=$("${A2[@]}" net init 2>&1) || fail "core 2 net init: $out"

start() { # N
    "$OC" --config "$T/core$1.conf" --key-file "$T/key$1" 2>>"$T/log$1" &
    eval "P$1=\$!"
    for _ in $(seq 50); do [ -S "$T/admin$1.sock" ] && break; sleep 0.1; done
    [ -S "$T/admin$1.sock" ] || fail "core $1 did not start"
}
stop() { # N
    eval "kill \$P$1; wait \$P$1"
    eval "P$1="
    rm -f "$T/admin$1.sock"
}
start 2
start 1
for _ in $(seq 100); do grep -q 'peer 2: up' "$T/log1" && break; sleep 0.1; done
grep -q 'peer 2: up (link .*OCSS 3)' "$T/log1" || fail "no OCSS 3 link"
grep -q 'routing table' "$T/log1" && fail "the cores disagree on the table"
api() { # N OP [ARG]
    local port=$API1 && [ "$1" = 2 ] && port=$API2
    "$API" "$port" "$PKI" portal "${@:2}"
}
expect "$(api 1 route.status)" "ok 1.0 5 5"
expect "$(api 2 route.status)" "ok 1.0 5 5"
out=$("$OC" admin --socket "$T/admin1.sock" status 2>&1) || fail "status: $out"
expect "$out" "blocks 5 (3 homed here), signed table 1"
expect "$out" "blocks homed on core 2: 2, peer linked"

# A delegate addition, to both cores
"$ROUTE" add "$T/del.key" "$T/route.tbl" "$T/a1.bin" --seq 1 --npa 472,US-NC --npa 945,US-TX >/dev/null || fail "add"
expect "$(api 1 route.offer "$T/a1.bin")" "ok 1.1 7 1"
expect "$(api 2 route.offer "$T/a1.bin")" "ok 1.1 7 1"
expect "$(api 2 route.offer "$T/a1.bin")" "ok 1.1 7 0" # again: held already
"$ROUTE" add "$T/other.key" "$T/route.tbl" "$T/x.bin" --seq 2 --npa 470,US-GA >/dev/null 2>&1 # no such key
"$ROUTE" keygen "$T/other.key" >/dev/null
"$ROUTE" add "$T/other.key" "$T/route.tbl" "$T/x.bin" --seq 2 --npa 470,US-GA >/dev/null || fail "add other"
expect "$(api 1 route.offer "$T/x.bin")" "invalid no valid delegation"
"$ROUTE" add "$T/del.key" "$T/route.tbl" "$T/gap.bin" --seq 3 --npa 470,US-GA,9 >/dev/null || fail "add gap"
expect "$(api 1 route.offer "$T/gap.bin")" "invalid out of order: at seq 1"
out=$("$OC" admin --socket "$T/admin1.sock" status 2>&1)
expect "$out" "blocks 7 (4 homed here)"

# Kept over a restart (the database's row), and core 2's view
stop 1
start 1
grep -q 'route: signed table 1.1, 7 blocks' "$T/log1" || fail "the addition was not reloaded"
expect "$(api 1 route.status)" "ok 1.1 7 7"
echo PASS
