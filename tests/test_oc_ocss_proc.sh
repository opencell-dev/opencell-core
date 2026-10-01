#!/bin/bash
# Two oc-core daemons joined by OCSS over TLS on 127.0.0.1 (core test
# services spec §9): core 1 dials core 2; a cell on core 1 (tool_oc_call)
# calls core 2's playback and echo services and core 1's own playback; the
# payloads come one per 120 ms (counted, the longest gap measured); the
# CDRs on both cores; core 2 stopping gives cause 5 at once, and core 1
# dials again when it is back; configs that can't work are refused.
#   test_oc_ocss_proc.sh OC_CORE TOOL_OC_CALL PKI
set -u
OC=$1
CALL=$2
PKI=$3
T=$(mktemp -d /tmp/oc_ocss_proc_XXXXXX) || exit 1
P1= P2=
cleanup() {
    [ -n "$P1" ] && kill "$P1" 2>/dev/null && wait "$P1" 2>/dev/null
    [ -n "$P2" ] && kill "$P2" 2>/dev/null && wait "$P2" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; for n in 1 2; do echo "--- core $n log"; cat "$T/log$n" 2>/dev/null; done; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
in_range() { [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]; }
PORT=$((20000 + RANDOM % 20000))
FPR1=$(cat "$PKI/core.fpr")
FPR2=$(cat "$PKI/core2.fpr")
for n in 1 2; do head -c 32 /dev/urandom >"$T/key$n" && chmod 0400 "$T/key$n"; done
head -c 180 /dev/urandom >"$T/clip.bit" # 10 payloads: 1.2 s

cat >"$T/core1.conf" <<EOF2
core_id = 1
key_id = 1
echo = +883160655500100
playback = +883160655500101
playback_clip = $T/clip.bit
block = 8831606 1
block = 8831503 2 2
db = $T/core1.db
cell_socket = $T/core1.sock
admin_socket = $T/admin1.sock
peer = 2 127.0.0.1:$PORT $FPR2
ocss_cert = $PKI/core.crt
ocss_key = $PKI/core.key
ocss_ca = $PKI/ca.crt
EOF2
cat >"$T/core2.conf" <<EOF2
core_id = 2
key_id = 2
echo = +883150355500100
playback = +883150355500101
playback_clip = $T/clip.bit
block = 8831503 2
block = 8831606 1 1
db = $T/core2.db
cell_socket = $T/core2.sock
admin_socket = $T/admin2.sock
peer = 1 - $FPR1
ocss_listen = 127.0.0.1:$PORT
ocss_cert = $PKI/core2.crt
ocss_key = $PKI/core2.key
ocss_ca = $PKI/ca.crt
EOF2

# Configs that can't work stop oc-core before anything starts.
refused() { # WHAT SED-EXPR MESSAGE
    sed "$2" "$T/core1.conf" >"$T/bad.conf"
    out=$(timeout 5 "$OC" --config "$T/bad.conf" --key-file "$T/key1" 2>&1); rc=$?
    [ "$rc" = 1 ] || fail "$1: exit $rc"
    expect "$out" "$3"
}
refused "a block homed on a core with no peer line" '/^peer/d' "add a peer = 2"
refused "a playback number with no clip" '/^playback_clip/d' "playback and playback_clip go together"
head -c 17 /dev/urandom >"$T/short.bit"
refused "a clip that is not whole payloads" "s|$T/clip.bit|$T/short.bit|" "a whole number of 18-byte payloads"
refused "a service number of another core's block" 's/^playback = .*/playback = +883150355500102/' \
    "not in a block this core is home for"
refused "a peer with a bad fingerprint" 's/^peer = 2 \(.*\) .*/peer = 2 \1 abc/' "CORE_ID ADDRESS|- SHA256"

"$CALL" hss "$T/hss.txt" || fail "tool_oc_call hss"
A1=("$OC" admin --offline --config "$T/core1.conf" --key-file "$T/key1")
A2=("$OC" admin --offline --config "$T/core2.conf" --key-file "$T/key2")
out=$("${A1[@]}" import-ocb-hss "$T/hss.txt" 2>&1) || fail "import: $out"
out=$("${A1[@]}" cell add 1 bench 2>&1) || fail "cell add: $out"
out=$("${A2[@]}" net init 2>&1) || fail "core 2 net init: $out"

start() { # N
    "$OC" --config "$T/core$1.conf" --key-file "$T/key$1" 2>>"$T/log$1" &
    eval "P$1=\$!"
    for _ in $(seq 50); do [ -S "$T/admin$1.sock" ] && break; sleep 0.1; done
    [ -S "$T/admin$1.sock" ] || fail "core $1 did not start"
}
linked() { # COUNT: wait for the COUNT-th "peer 2: up" in core 1's log
    for _ in $(seq 100); do [ "$(grep -c 'peer 2: up' "$T/log1")" -ge "$1" ] && return 0; sleep 0.1; done
    fail "core 1 did not link to core 2 (time $1)"
}
call() { # CALLED SECONDS -> "media N maxgap G" on stdout
    "$CALL" "$T/core1.sock" 1 7 "$1" "$2" >"$T/call" || fail "call to $1: $(cat "$T/call")"
    expect "$(cat "$T/call")" "answered"
    grep '^media' "$T/call"
    echo "$1: $(grep '^media' "$T/call")" >&2
}

start 2
start 1
linked 1
out=$("$OC" admin --socket "$T/admin1.sock" status 2>&1) || fail "status: $out"
expect "$out" "block 8831503: home core 2, peer linked"
expect "$out" "playback +883160655500101: clip of 10 payloads (1.20 s)"
grep -q 'ocss: 127.0.0.1:[0-9]*: core 1, certificate .*, accepted' "$T/log2" || fail "core 2 did not log core 1's certificate"

read -r _ n _ gap <<<"$(call +883150355500101 3)" # core 2's playback, through core 1
in_range "$n" 20 28 || fail "core 2's playback: $n payloads in 3 s (25 expected)"
[ "$gap" -lt 300 ] || fail "core 2's playback: a gap of $gap ms"
read -r _ n _ gap <<<"$(call +883150355500100 2)" # core 2's echo: every payload comes back
in_range "$n" 12 18 || fail "core 2's echo: $n payloads back in 2 s"
read -r _ n _ gap <<<"$(call +883160655500101 2)" # core 1's own playback
in_range "$n" 13 19 || fail "core 1's playback: $n payloads in 2 s"
[ "$gap" -lt 300 ] || fail "core 1's playback: a gap of $gap ms"
grep -q 'playback sent [0-9]* payloads, skipped 0' "$T/log2" || fail "core 2 skipped payloads on an idle loop"

out=$("$OC" admin --socket "$T/admin2.sock" cdr 2>&1) || fail "core 2 cdr: $out"
expect "$out" "+883160655501234 -> +883150355500101  cells 0 -> 0  answered"
expect "$out" "+883160655501234 -> +883150355500100  cells 0 -> 0  answered"
out=$("$OC" admin --socket "$T/admin1.sock" cdr 2>&1) || fail "core 1 cdr: $out"
expect "$out" "+883160655501234 -> +883150355500101  cells 1 -> 0  answered"

kill "$P2" && wait "$P2"; P2=
for _ in $(seq 50); do grep -q 'peer 2: link down' "$T/log1" && break; sleep 0.1; done
grep -q 'peer 2: link down' "$T/log1" || fail "core 1 did not see core 2 go"
"$CALL" "$T/core1.sock" 1 7 +883150355500100 2 >"$T/call"
expect "$(cat "$T/call")" "released cause 5"
out=$("$OC" admin --socket "$T/admin1.sock" status 2>&1) || fail "status: $out"
expect "$out" "block 8831503: home core 2, peer NOT linked"
start 2
linked 2
echo "all passed"
