#!/bin/bash
# oc-core as a process (network-core spec §9.4, §17 decisions 1 and 8):
# first setup offline, the daemon on its sockets, admin over the socket, the
# lock against --offline while it runs, a cell's HELLO, a clean stop on
# SIGTERM, data kept across a restart, the key from a systemd credential
# directory, a wrong or exposed master key refused, and a call that is up
# when the daemon stops ended with its CDR written.
#   test_oc_core_proc.sh OC_CORE TOOL_OC_HELLO TOOL_OC_DRIP TOOL_OC_CALL
# Everything it makes is in one temp directory, removed on exit; the
# processes it starts are stopped by PID.
set -u
OC=$1
HELLO=$2
DRIP=$3
CALL=$4
T=$(mktemp -d /tmp/oc_core_proc_XXXXXX) || exit 1
PID=
HPID=
DPID=
CPID=
cleanup() {
    [ -n "$HPID" ] && kill "$HPID" 2>/dev/null
    [ -n "$CPID" ] && kill "$CPID" 2>/dev/null
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
    [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- daemon log"; cat "$T/log" 2>/dev/null; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
ME=$(id -u)
ms_since() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

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
# First setup on a fresh machine: the database's directory is made (0700).
# Under root's umask 077 too: the parents it makes stay reachable (0755).
out=$(umask 077; "$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/fresh/core/core.db" \
      net init 2>&1) || fail "net init in a missing directory: $out"
[ "$(stat -c %a "$T/fresh/core")" = 700 ] || fail "made the database directory $(stat -c %a "$T/fresh/core")"
[ "$(stat -c %a "$T/fresh")" = 755 ] || fail "made its parent $(stat -c %a "$T/fresh") under umask 077"

# The client counts the answer against its head ("RC BYTES\n"): a cut one fails.
client_vs() {
    "$DRIP" --serve "$T/fake.sock" "$1" >"$T/serve" &
    local fpid=$!
    for _ in $(seq 50); do [ -S "$T/fake.sock" ] && break; sleep 0.05; done
    out=$("$OC" admin --socket "$T/fake.sock" status 2>&1); rc=$?
    wait "$fpid"
}
client_vs $'0 100\nshort\n'
[ "$rc" = 1 ] || fail "a cut answer exited $rc: $out"
expect "$out" "answer cut short"
client_vs $'0 6\nhello\n'
[ "$rc" = 0 ] || fail "a whole answer exited $rc: $out"
expect "$out" "^hello$"
client_vs $'0\nhello\n'
[ "$rc" = 1 ] || fail "an answer with no count exited $rc: $out"
expect "$out" "no answer from oc-core"
# rc 2 with no sudo field sent (not root): the answer stands, no retry.
client_vs $'2 6\nusage\n'
[ "$rc" = 2 ] || fail "a usage answer exited $rc: $out"
expect "$out" "^usage$"
expect "$(cat "$T/serve")" "^request: status$"

DB=$T/core.db
start() {
    "$OC" --config "$T/oc-core.conf" --db "$DB" "$@" 2>>"$T/log" &
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

# A slow admin peer holds the daemon ADMIN_IO_S (2 s) at most, however it
# spaces its bytes: then it is dropped and the next command is served.
"$DRIP" "$T/admin.sock" 1000 20 >"$T/drip" &
DPID=$!
sleep 0.3
t0=$(date +%s%N)
out=$("$OC" admin --socket "$T/admin.sock" status 2>&1) || fail "status behind a slow peer: $out"
ms=$(ms_since "$t0")
[ "$ms" -lt 3000 ] || fail "status waited $ms ms behind a slow admin peer"
wait "$DPID"; DPID=
expect "$(cat "$T/drip")" "closed after"
grep -q 'admin (uid [0-9]*): the request was dropped: it took more than 2 s' "$T/log" || fail "the slow peer was not logged"

# An answer bigger than the socket takes, to a peer that doesn't read it:
# dropped when its 2 s are up, and the peer can tell it is cut. The real
# client takes the same answer whole.
out=$("$DRIP" --flood "$T/admin.sock" 4000 "a-command-that-is-not-one-but-is-audited-all-the-same") || fail "flood: $out"
out=$("$OC" admin --socket "$T/admin.sock" audit 10000 2>/dev/null) || fail "audit 10000 failed"
[ "$(wc -c <<<"$out")" -gt 300000 ] || fail "audit 10000 is only $(wc -c <<<"$out") bytes"
out=$("$DRIP" --late-read "$T/admin.sock" 3 audit 10000) || fail "late read: $out"
expect "$out" "^cut$"
grep -q 'admin (uid [0-9]*): the answer was dropped: it took more than 2 s' "$T/log" || fail "the slow reader was not logged"
"$DRIP" --hang-up "$T/admin.sock" audit 10000 || fail "hang-up"
for _ in $(seq 30); do grep -q 'the answer was dropped: the peer closed its connection' "$T/log" && break; sleep 0.1; done
grep -q 'admin (uid [0-9]*): the answer was dropped: the peer closed its connection' "$T/log" ||
    fail "a peer that hung up was not logged as such"

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
out=$("$OC" admin --socket "$T/admin.sock" audit 10000 2>&1) || fail "audit: $out"
expect "$out" "ADMIN .* u$ME net init"
expect "$out" "ADMIN .* u$ME cell mode 1 part97"
expect "$out" "CELL_REJECT"
out=$("$OC" admin --socket "$T/admin.sock" cell list 2>&1)
expect "$out" 'cell 1 "bench": part97'
# SIGTERM while a slow admin peer is being served: out within a second.
"$DRIP" "$T/admin.sock" 1000 20 >/dev/null &
DPID=$!
sleep 0.3
t0=$(date +%s%N)
kill -TERM "$PID"
for _ in $(seq 40); do kill -0 "$PID" 2>/dev/null || break; sleep 0.05; done
ms=$(ms_since "$t0")
kill -0 "$PID" 2>/dev/null && fail "SIGTERM held by a slow admin peer ($ms ms)"
[ "$ms" -lt 1000 ] || fail "SIGTERM took $ms ms with a slow admin peer"
grep -q 'admin (uid [0-9]*): the request was dropped: oc-core is stopping' "$T/log" ||
    fail "the peer dropped at SIGTERM was not logged as such"
wait "$PID"; rc=$?; PID=
[ "$rc" = 0 ] || fail "exit status $rc after SIGTERM"
kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=

# A call that is up when oc-core stops ends there (cause 5, spec §7.6 and
# §7.10), and its CDR is written before the database closes (§3: a CDR per
# call attempt): the restarted core lists it.
DB=$T/call.db
CADM=("$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key" --db "$DB")
"$CALL" hss "$T/hss.txt" || fail "tool_oc_call hss"
out=$("${CADM[@]}" import-ocb-hss "$T/hss.txt" 2>&1) || fail "import: $out"
out=$("${CADM[@]}" cell add 1 bench 2>&1) || fail "cell add: $out"
start --key-file "$T/key"
"$CALL" "$T/core.sock" 1 7 >"$T/call" &
CPID=$!
for _ in $(seq 100); do grep -q answered "$T/call" && break; sleep 0.1; done
grep -q answered "$T/call" || fail "the echo call was not answered: $(cat "$T/call")"
out=$("$OC" admin --socket "$T/admin.sock" cdr 2>&1) || fail "cdr: $out"
[ -z "$out" ] || fail "a CDR before the call ended: $out"
stop
wait "$CPID"; CPID=
expect "$(cat "$T/call")" "closed"
grep -q 'call 00000042/[0-9a-f]* ended, cause 5' "$T/log" || fail "the call was not ended at the stop"
start --key-file "$T/key"
out=$("$OC" admin --socket "$T/admin.sock" cdr 2>&1) || fail "cdr after the restart: $out"
expect "$out" "^#1 +883160655501234 -> +883160655500100  cells 1 -> 0  answered, [0-9]* s, cause 5$"
out=$("$OC" admin --socket "$T/admin.sock" loc 2>&1) || fail "loc after the restart: $out"
expect "$out" "^+883160655501234  cell 1  tmid 76ad0488  expires in [0-9]* s$" # the stop left locations alone
stop
DB=$T/core.db

# `sudo oc-core admin ...` over the socket: the client, as root, sends its
# SUDO_UID and the daemon records the claim as "u0 (sudo uN)". Not as root,
# the client sends none, and a peer that is not root sending one is refused,
# nothing run.
start --key-file "$T/key"
out=$(SUDO_UID=4242 "$OC" admin --socket "$T/admin.sock" status 2>&1) || fail "status with SUDO_UID: $out"
out=$("$DRIP" --late-read "$T/admin.sock" 0 --sudo-uid=4242 status) || fail "sudo field: $out"
expect "$out" "^rc 2$"
grep -q "admin (uid $ME): a --word from a peer that is not root: refused" "$T/log" ||
    fail "a --word from a peer that is not root was not logged"
out=$("$DRIP" --late-read "$T/admin.sock" 0 --frob status) || fail "--frob: $out"
expect "$out" "^rc 2$"
out=$("$OC" admin --socket "$T/admin.sock" audit 3 2>&1) || fail "audit: $out"
expect "$out" "ADMIN .* u$ME status"
[ "$(grep -c "ADMIN .* refused: --word from u$ME\$" <<<"$out")" = 2 ] ||
    fail "the refused --words are not audited (a security event): $out"
grep -q "4242" <<<"$out" && fail "a sudo uid was recorded for a peer that is not root: $out"
stop
# As root in a user namespace (the daemon too, so the peer is uid 0 to it).
if unshare -r true 2>/dev/null; then
    timeout 30 unshare -r bash -c '
        OC=$1 T=$2 DRIP=$3
        "$OC" --config "$T/oc-core.conf" --db "$T/core.db" --key-file "$T/key" 2>>"$T/log" &
        pid=$!
        trap "kill $pid 2>/dev/null" EXIT
        for _ in $(seq 50); do [ -S "$T/admin.sock" ] && break; sleep 0.1; done
        SUDO_UID=4242 "$OC" admin --socket "$T/admin.sock" status >/dev/null || echo "status failed"
        SUDO_UID=12x "$OC" admin --socket "$T/admin.sock" cell list >/dev/null || echo "cell list failed"
        "$DRIP" --late-read "$T/admin.sock" 0 --sudo-uid=01 status | grep -q "^rc 2$" || echo "01 not refused"
        "$OC" admin --socket "$T/admin.sock" audit 4
        kill -TERM $pid
        wait $pid || echo "exit status $?"
        # A daemon older than the field (v0.1.0) takes it for a command and
        # answers usage: the client asks once more without it.
        nl=$(printf "\nx") && nl=${nl%x}
        "$DRIP" --serve "$T/fake.sock" "2 6${nl}usage${nl}" "0 3${nl}ok${nl}" >"$T/serve" &
        fpid=$!
        for _ in $(seq 50); do [ -S "$T/fake.sock" ] && break; sleep 0.05; done
        SUDO_UID=4242 "$OC" admin --socket "$T/fake.sock" status || echo "old daemon: failed"
        wait $fpid || echo "fake daemon: exit status $?"
    ' _ "$OC" "$T" "$DRIP" >"$T/userns" 2>&1
    out=$(cat "$T/userns")
    grep -q "failed\|exit status\|not refused" <<<"$out" && fail "as root in a user namespace: $out"
    expect "$out" "ADMIN .* u0 (sudo u4242) status"
    expect "$out" "ADMIN .* u0 cell list" # SUDO_UID not a number: no claim sent
    expect "$out" "ADMIN .* refused: bad --word from u0$"
    grep -q 'admin (uid 0, sudo u4242): status -> 0' "$T/log" || fail "the sudo uid is not in the log line"
    grep -q 'admin (uid 0): a malformed sudo field or unknown --word: refused' "$T/log" ||
        fail "a root peer's bad --word was not logged"
    expect "$out" "^ok$"
    expect "$(cat "$T/serve")" "^request: --sudo-uid=4242 status$"
    expect "$(cat "$T/serve")" "^request: status$"
else
    echo "note: no user namespaces here: the root client's sudo uid is not tried"
fi

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
