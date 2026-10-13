#!/bin/bash
# oc-core's cell listener (single-board cell spec §5): cells over TLS with
# the cell role, let in only with the pin stored for their cell_id, next to
# the Unix socket; the HELLO gate; the config's all-or-none rule; cell cert
# dropping a live TLS link.
#   test_oc_cell_tls_proc.sh OC_CORE TOOL_OC_HELLO TOOL_OC_CALL PKI
set -u
OC=$1
HELLO=$2
CALL=$3
PKI=$4
T=$(mktemp -d /tmp/oc_cell_tls_XXXXXX) || exit 1
PID=
BG=()
cleanup() {
    for p in "${BG[@]}"; do kill "$p" 2>/dev/null; done
    [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- daemon log"; cat "$T/log" 2>/dev/null; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
check() { echo "ok: $1"; }
PORT=$(( 20000 + $$ % 20000 ))
TLS="tls:localhost:$PORT:$PKI:cell"

head -c 32 /dev/urandom >"$T/key" && chmod 0400 "$T/key"
conf() {
    cat >"$T/oc-core.conf" <<EOF
core_id = 1
key_id = 1
name = oc-core-test
block = 8831606 1
cell_socket = $T/core.sock
admin_socket = $T/admin.sock
$*
EOF
}
CELL_CONF="cell_listen = 127.0.0.1:$PORT
cell_cert = $PKI/core.crt
cell_key = $PKI/core.key
cell_ca = $PKI/ca.crt"
adm() { "$OC" admin --socket "$T/admin.sock" "$@" 2>&1; }
off() { "$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" "$@" 2>&1; }

# All four or none.
conf "$(grep -v cell_ca <<<"$CELL_CONF")"
out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>&1) && fail "started without cell_ca"
expect "$out" "cell_listen is set: cell_ca is needed too"
conf "$(grep -v cell_listen <<<"$CELL_CONF")"
out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>&1) && fail "started with cell_* but no cell_listen"
expect "$out" "cell_\* is set but cell_listen is not"
check "the cell_* keys are all or none"

conf "$CELL_CONF"
"$CALL" hss "$T/hss.txt" || fail "tool_oc_call hss"
out=$(off import-ocb-hss "$T/hss.txt") || fail "import: $out" # the network key too (no net init)
off cell add 1 bench >/dev/null || fail "cell add 1"
off cell add 2 other >/dev/null || fail "cell add 2"
"$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>>"$T/log" &
PID=$!
for _ in $(seq 50); do adm status >/dev/null && break; sleep 0.1; done
expect "$(cat "$T/log")" "cells on $T/core.sock and 127.0.0.1:$PORT (TLS)"

out=$("$HELLO" "$TLS" 1 7 1)
expect "$out" "HELLO_NAK reason 1"
expect "$(cat "$T/log")" "cell 1: no certificate pinned"
check "an unpinned cell is refused as unknown"

adm cell cert 1 "$(cat "$PKI/portal.fpr")" >/dev/null
out=$("$HELLO" "$TLS" 1 7 1)
expect "$out" "HELLO_NAK reason 1"
expect "$(cat "$T/log")" "cell 1: certificate differs from the pin: certificate $(cut -c1-16 "$PKI/cell.fpr")"
check "a cell whose pin differs is refused as unknown"

out=$("$HELLO" "$TLS" 9 7 1)
expect "$out" "HELLO_NAK reason 1"
check "an unknown cell over TLS is refused"

out=$("$HELLO" "tls:localhost:$PORT:$PKI:portal" 1 7 1)
expect "$out" "TLS refused"
check "a portal certificate gets no TLS session"

adm cell cert 1 "$(cat "$PKI/cell.fpr")" >/dev/null
out=$("$HELLO" "$TLS" 1 7 2) || fail "pinned HELLO: $out"
expect "$out" "HELLO_ACK mode"
check "the pinned cell is let in"

out=$("$HELLO" "$TLS" 1 hello-ping 1) || fail "hello-ping: $out"
expect "$out" "HELLO_ACK mode"
expect "$out" "PONG"
check "a frame right behind HELLO is served"

out=$("$HELLO" "$TLS" 1 ping-first 1)
expect "$out" "closed"
expect "$(cat "$T/log")" "first frame is not HELLO"
check "a first frame other than HELLO closes the link"

exec 7<>/dev/tcp/127.0.0.1/$PORT # TCP and nothing else: the handshake times out
sleep 11
expect "$(cat "$T/log")" "no handshake in 10 s"
exec 7>&-
check "a silent TCP connection is closed after 10 s"

"$HELLO" "$TLS" 1 ping-none 12 >"$T/silent" &   # handshake, then no frame at all
BG+=($!)
sleep 11.5
expect "$(cat "$T/log")" "no HELLO in 10 s"
check "a TLS cell that never says HELLO is closed"

"$HELLO" "$TLS" 1 7 6 >"$T/first" &
BG+=($!)
sleep 1
out=$("$HELLO" "$TLS" 1 8 1) || fail "second link: $out"
expect "$out" "HELLO_ACK mode"
check "a second TLS link for the same cell is let in"

"$HELLO" "$T/core.sock" 2 7 3 >"$T/unix" &
BG+=($!)
sleep 0.5
out=$("$HELLO" "$TLS" 1 9 1) || fail "TLS beside Unix: $out"
wait "${BG[-1]}" || fail "the Unix cell beside a TLS cell: $(cat "$T/unix")"
check "a Unix cell and a TLS cell at once"

"$CALL" "$TLS" 1 11 >"$T/call" &
BG+=($!)
for _ in $(seq 100); do grep -q answered "$T/call" && break; sleep 0.1; done
expect "$(cat "$T/call")" "answered"
check "registration and an echo call over TLS (AV_RES and MEDIA through TLS)"

"$HELLO" "$TLS" 1 12 8 >"$T/held" &
BG+=($!)
sleep 1
out=$(adm cell cert 1 none)
expect "$out" "its link was dropped"
for _ in $(seq 30); do grep -q closed "$T/held" && break; sleep 0.1; done
expect "$(cat "$T/held")" "closed"
out=$("$HELLO" "$TLS" 1 13 1)
expect "$out" "HELLO_NAK reason 1"
check "cell cert none drops the TLS link"

# A link let in as cell 1 can't become cell 2 (unpinned) by a second HELLO.
adm cell cert 1 "$(cat "$PKI/cell.fpr")" >/dev/null
"$HELLO" "$TLS" 1 hello-other 3 >"$T/other" &
BG+=($!)
for _ in $(seq 20); do grep -q "HELLO_NAK\|closed" "$T/other" && break; sleep 0.1; done
sleep 0.3
expect "$(adm cell list)" 'cell 2 "other".*not linked'
wait "${BG[-1]}"
out=$(cat "$T/other")
expect "$out" "HELLO_ACK mode"
grep -q "HELLO_NAK reason 1\|closed" <<<"$out" || fail "hello-other: no HELLO_NAK: $out"
expect "$(cat "$T/log")" "let in as cell 1, HELLO names cell 2"
check "a second HELLO for another cell is refused, and that cell is not linked"

# Behind the HELLO gate, 4 links at most: silent cell certificates can't
# take every link slot (shared with the Unix cells).
SILENT=()
for i in 1 2 3 4; do
    "$HELLO" "$TLS" 1 ping-none 20 >"$T/gated$i" &
    BG+=($!)
    SILENT+=($!)
done
sleep 1
t0=$(date +%s%N)
out=$("$HELLO" "$TLS" 1 ping-none 3)
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
expect "$out" "closed"
[ "$ms" -lt 2000 ] || fail "the fifth silent TLS link was held $ms ms"
expect "$(cat "$T/log")" "4 links behind the HELLO gate already, connection refused"
out=$("$HELLO" "$T/core.sock" 2 7 1) || fail "Unix cell beside 4 gated links: $out"
expect "$out" "HELLO_ACK mode"
kill "${SILENT[@]}" 2>/dev/null
wait "${SILENT[@]}" 2>/dev/null
check "at most 4 TLS links behind the HELLO gate; a Unix cell still gets in"
echo "PASS"
