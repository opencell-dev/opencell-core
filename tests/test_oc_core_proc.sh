#!/bin/bash
# oc-core as a process (network-core spec §9.4, §17 decisions 1 and 8):
# first setup offline, the daemon on its sockets, admin over the socket, the
# lock against --offline while it runs, a cell's HELLO, a clean stop on
# SIGTERM, data kept across a restart, the key from a systemd credential
# directory, and a wrong or exposed master key refused.
#   test_oc_core_proc.sh OC_CORE TOOL_OC_HELLO
# Everything it makes is in one temp directory, removed on exit; the
# processes it starts are stopped by PID.
set -u
OC=$1
HELLO=$2
T=$(mktemp -d /tmp/oc_core_proc_XXXXXX) || exit 1
PID=
HPID=
cleanup() {
    [ -n "$HPID" ] && kill "$HPID" 2>/dev/null
    [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- daemon log"; cat "$T/log" 2>/dev/null; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
ME=$(id -u)

head -c 32 /dev/urandom >"$T/key" && chmod 0400 "$T/key"
cat >"$T/oc-core.conf" <<EOF
core_id = 1
key_id = 1
echo = +883160655500100
block = 8831606 1
db = $T/elsewhere.db
cell_socket = $T/core.sock
admin_socket = $T/admin.sock
EOF
ADM=("$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db")

out=$("$OC" --version) || fail "--version"
expect "$out" "^oc-core "
"$OC" --frob >/dev/null 2>&1; [ $? = 2 ] || fail "a bad option is not usage (2)"
"$OC" admin >/dev/null 2>&1; [ $? = 2 ] || fail "admin with no command is not usage (2)"

out=$("${ADM[@]}" net init 2>&1) || fail "net init: $out"
out=$("${ADM[@]}" cell add 1 bench 2>&1) || fail "cell add: $out"
out=$("${ADM[@]}" sub add +883-1-606-555-01234 2>&1) || fail "sub add: $out"
expect "$out" "+883160655501234"
[ -e "$T/elsewhere.db" ] && fail "--db did not override the config's db"

start() {
    "$OC" --config "$T/oc-core.conf" --db "$T/core.db" "$@" 2>>"$T/log" &
    PID=$!
    for _ in $(seq 50); do [ -S "$T/admin.sock" ] && return 0; sleep 0.1; done
    fail "the admin socket did not appear"
}
stop() {
    kill -TERM "$PID"
    for _ in $(seq 30); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$PID" 2>/dev/null && fail "no exit 3 s after SIGTERM"
    wait "$PID"; rc=$?; PID=
    [ "$rc" = 0 ] || fail "exit status $rc after SIGTERM"
}

start --key-file "$T/key"
out=$("$OC" admin --socket "$T/admin.sock" status 2>&1) || fail "status: $out"
expect "$out" "running"
expect "$out" "subscribers 1"
[ "$(stat -c %a "$T/core.sock")" = 600 ] || fail "cell socket mode $(stat -c %a "$T/core.sock")"
[ "$(stat -c %a "$T/admin.sock")" = 600 ] || fail "admin socket mode $(stat -c %a "$T/admin.sock")"
out=$("${ADM[@]}" status 2>&1) && fail "--offline ran while the daemon holds the database"
expect "$out" "is in use (oc-core is running"

out=$("$HELLO" "$T/core.sock" 1 7 3) || fail "HELLO: $out"
expect "$out" "HELLO_ACK mode 1 period 1800"
"$HELLO" "$T/core.sock" 1 7 4 >"$T/hello" &
HPID=$!
sleep 1
out=$("$OC" admin --config "$T/oc-core.conf" status 2>&1) || fail "status via config: $out"
expect "$out" 'cell 1 "bench": part15, enabled, list 0, linked'
out=$("$OC" admin --socket "$T/admin.sock" cell mode 1 part97 2>&1) || fail "cell mode: $out"
expect "$out" "its link was dropped"
wait "$HPID"; HPID=
expect "$(cat "$T/hello")" "closed"
out=$("$HELLO" "$T/core.sock" 9 7 1)
expect "$out" "HELLO_NAK reason 1"

# A peer's words must not become lines of their own in the journal.
out=$("$OC" admin --socket "$T/admin.sock" $'status\n<3>oc-core: forged' 2>&1); [ $? = 2 ] || fail "forged: $out"
grep -q '^<3>oc-core: forged' "$T/log" && fail "an admin peer wrote a line of its own into the log"
grep -q 'admin (uid [0-9]*): status?<3>oc-core: forged' "$T/log" || fail "the forged command was not logged cleaned"

stop
[ -e "$T/admin.sock" ] && fail "admin socket left behind"
[ -e "$T/core.sock" ] && fail "cell socket left behind"
grep -q '^<5>oc-core: stopping' "$T/log" || fail "no journald-prefixed stop line"

# The key from a systemd credential directory (LoadCredential=master.key).
# On tmpfs systemd makes it root's, 0400, plus an ACL entry for the service's
# user, which stat() shows as 0440; here the entry is for this user.
mkdir "$T/cred" && cp "$T/key" "$T/cred/master.key" && chmod 0400 "$T/cred/master.key"
if command -v setfacl >/dev/null && setfacl -m "u:$ME:r" "$T/cred/master.key" 2>/dev/null; then
    [ "$(stat -c %a "$T/cred/master.key")" = 440 ] || fail "ACL'd credential mode $(stat -c %a "$T/cred/master.key")"
else
    echo "note: no setfacl or no ACLs here: the credential is tried without its ACL"
fi
CREDENTIALS_DIRECTORY="$T/cred" start
out=$("$OC" admin --socket "$T/admin.sock" audit 20 2>&1) || fail "audit: $out"
expect "$out" "ADMIN .* u$ME net init"
expect "$out" "ADMIN .* u$ME cell mode 1 part97"
expect "$out" "CELL_REJECT"
out=$("$OC" admin --socket "$T/admin.sock" cell list 2>&1)
expect "$out" 'cell 1 "bench": part97'
stop

out=$(env -u CREDENTIALS_DIRECTORY "$OC" --config "$T/oc-core.conf" --db "$T/core.db" 2>&1) && fail "started with no key"
expect "$out" "no master key"
head -c 32 /dev/urandom >"$T/key2" && chmod 0400 "$T/key2"
out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key2" --db "$T/core.db" 2>&1) && fail "started with the wrong key"
expect "$out" "the master key does not open this database"
chmod 0644 "$T/key"
out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>&1) && fail "started with a readable key"
expect "$out" "accessible by group or others"
out=$("$OC" admin --socket "$T/admin.sock" status 2>&1) && fail "admin without a daemon"
expect "$out" "oc-core is not running"

echo "OK"
