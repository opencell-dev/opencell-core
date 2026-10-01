#!/bin/bash
# oc-core's admin API as a process (portal spec §7): the listener on a
# private address only, who gets in (the pinned portal certificate, with
# its role and ALPN) and who doesn't, a call audited with its account, the
# rate limit from the config, and peers that are slow or too many: none of
# them holds up a cell or another API client, and SIGTERM still stops the
# daemon at once.
#   test_oc_api_proc.sh OC_CORE TOOL_OC_API TOOL_OC_HELLO PKI
# PKI is the test PKI (test_oc_ca.sh). Everything else is in one temp
# directory, removed on exit; processes are stopped by PID.
set -u
OC=$1
API=$2
HELLO=$3
PKI=$4
T=$(mktemp -d /tmp/oc_api_proc_XXXXXX) || exit 1
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
ms_since() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
PORT=$(( 20000 + $$ % 20000 ))

head -c 32 /dev/urandom >"$T/key" && chmod 0400 "$T/key"
conf() { # the config, with the API lines given
    cat >"$T/oc-core.conf" <<EOF
core_id = 1
key_id = 1
name = oc-core-test
block = 8831606 1
block = 8831717 2
cell_socket = $T/core.sock
admin_socket = $T/admin.sock
$*
EOF
}
API_CONF="api_listen = 127.0.0.1:$PORT
api_cert = $PKI/core.crt
api_key = core.key
api_ca = $PKI/ca.crt
api_portal_fpr = $(cat "$PKI/portal.fpr")
api_rate = num.check 3600 3"
conf "$API_CONF"
out=$("$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" net init 2>&1) ||
    fail "net init: $out"
out=$("$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" cell add 1 bench 2>&1) ||
    fail "cell add: $out"

# The key as a systemd credential, by name (api_key = core.key).
mkdir -p "$T/creds" && cp "$PKI/core.key" "$T/creds/core.key"
start() {
    CREDENTIALS_DIRECTORY=$T/creds "$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>>"$T/log" &
    PID=$!
    for _ in $(seq 50); do
        out=$("$API" "$PORT" "$PKI" portal core.status 2>&1)
        grep -q '^ok' <<<"$out" && return 0
        kill -0 "$PID" 2>/dev/null || fail "oc-core exited"
        sleep 0.1
    done
    fail "the API did not answer: $out"
}
stop() {
    kill -TERM "$PID"
    for _ in $(seq 30); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$PID" 2>/dev/null && fail "no exit 3 s after SIGTERM"
    wait "$PID"; rc=$?; PID=
    [ "$rc" = 0 ] || fail "exit status $rc after SIGTERM"
}

# Never public: a public address or none at all, and oc-core won't start.
for bad in "api_listen = 8.8.8.8:$PORT" "api_listen = 0.0.0.0:$PORT" "api_listen = [2001:db8::1]:$PORT"; do
    conf "${API_CONF/api_listen = 127.0.0.1:$PORT/$bad}"
    out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>&1) && fail "started with $bad"
    expect "$out" "not a private address"
done
conf "$(grep -v api_portal_fpr <<<"$API_CONF")"
out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>&1) && fail "started with no pin"
expect "$out" "api_portal_fpr is needed too"

# Binding at boot: an api_listen address that is not up yet (10.0.0.60
# before its interface is) does not stop the core: the cells are served.
conf "${API_CONF/api_listen = 127.0.0.1:$PORT/api_listen = 10.255.254.253:$PORT}"
CREDENTIALS_DIRECTORY=$T/creds "$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>>"$T/log" &
PID=$!
for _ in $(seq 30); do
    out=$("$HELLO" "$T/core.sock" 1 7 0 2>&1) && break
    kill -0 "$PID" 2>/dev/null || fail "oc-core exited with api_listen on an address not up yet"
    sleep 0.1
done
expect "$out" "HELLO_ACK"
expect "$(cat "$T/log")" "API 10.255.254.253:$PORT"
stop
conf "$API_CONF"

start
out=$("$API" "$PORT" "$PKI" portal core.status) || fail "core.status: $out"
expect "$out" "^ok oc-core-test "
out=$("$API" "$PORT" "$PKI" portal --actor 42 sub.create +883171746412345)
expect "$out" "^ok"
expect "$out" "opencell:2:"
out=$("$API" "$PORT" "$PKI" portal --actor 43 sub.create +883171746412345)
expect "$out" "^taken"
out=$("$OC" admin --socket "$T/admin.sock" audit 5 2>&1)
expect "$out" "API          +883171746412345  tmid 00000000  cell 0  a43 sub.create taken"
expect "$out" "a42 sub.create ok"

# Who doesn't get in.
expect "$("$API" "$PORT" "$PKI" other core.status)" "^refused"
expect "$("$API" "$PORT" "$PKI" cell core.status)" "^refused"
expect "$("$API" "$PORT" "$PKI" rogue core.status)" "^refused"
expect "$("$API" "$PORT" "$PKI" none core.status)" "^refused"
expect "$("$API" "$PORT" "$PKI" portal --alpn oc-cell/1 core.status)" "^refused"
expect "$("$API" "$PORT" "$PKI" portal --alpn none core.status)" "^refused"
sleep 0.2
expect "$(cat "$T/log")" "is not pinned"
expect "$(cat "$T/log")" "does not speak oc-admin/1"

# The config's rate limit: num.check 3 at once.
for _ in 1 2 3; do expect "$("$API" "$PORT" "$PKI" portal num.check +883171746400001)" "^ok"; done
expect "$("$API" "$PORT" "$PKI" portal num.check +883171746400001)" "^rate_limited"

# Pipelined: more requests at once than one loop turn serves (16), all
# answered in order at once, not at the 10 s answer deadline.
out=$("$API" "$PORT" "$PKI" portal pipe 40)
expect "$out" "^answered 40 in"
ms=$(sed -n 's/^answered 40 in \([0-9]*\) ms$/\1/p' <<<"$out")
[ "$ms" -lt 1000 ] || fail "40 pipelined calls took $ms ms"

# Slow peers: a TCP connection that never starts TLS, a client that sends
# half a request, one that sits idle. None holds up a cell's HELLO or
# another client's call; the first two are dropped at their 5 s deadline.
exec 3<>/dev/tcp/127.0.0.1/"$PORT"
"$API" "$PORT" "$PKI" portal drip 8 >"$T/drip" &
BG+=($!)
"$API" "$PORT" "$PKI" portal hold 8 >"$T/hold" &
BG+=($!)
sleep 0.5
t0=$(date +%s%N)
out=$("$HELLO" "$T/core.sock" 1 7 0) || fail "HELLO while the API has slow peers: $out"
expect "$out" "HELLO_ACK"
out=$("$API" "$PORT" "$PKI" portal core.status)
expect "$out" "^ok"
[ "$(ms_since "$t0")" -lt 1000 ] || fail "a cell and an API call took $(ms_since "$t0") ms beside slow peers"
wait "${BG[@]}"
BG=()
expect "$(cat "$T/drip")" "closed after [5-6] s"
expect "$(cat "$T/hold")" "^open"
exec 3>&-
expect "$(cat "$T/log")" "the handshake took more than 5 s"
expect "$(cat "$T/log")" "a request took more than 5 s"

# Too many: 4 connections at most; a fifth is closed at once, and once the
# four are gone, a client gets in again.
for i in 3 4 5 6; do eval "exec $i<>/dev/tcp/127.0.0.1/$PORT"; done
sleep 0.3
expect "$("$API" "$PORT" "$PKI" portal core.status)" "^refused"
expect "$(cat "$T/log")" "connections open already"
for i in 3 4 5 6; do eval "exec $i>&-"; done
sleep 0.5
expect "$("$API" "$PORT" "$PKI" portal core.status)" "^ok"

# SIGTERM with a handshake hanging: the daemon still stops at once.
exec 3<>/dev/tcp/127.0.0.1/"$PORT"
sleep 0.2
t0=$(date +%s%N)
stop
[ "$(ms_since "$t0")" -lt 1000 ] || fail "SIGTERM took $(ms_since "$t0") ms with a handshake pending"
exec 3>&-
echo "all passed"
