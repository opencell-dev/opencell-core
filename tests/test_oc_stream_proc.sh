#!/bin/bash
# Stream channels as a process (streaming channel spec 2026-11-01 §7): with
# a fake ffmpeg (a script in place of stream_ffmpeg), oc-core fetches only
# while a call is on a channel and stops the fetch 5 s after the last; the
# fetch runs confined (it can't read a file outside the system's, nor open a
# Unix socket: the fake checks, and gives no audio if it can); a call hears
# live audio; a fetch that dies, or never gives audio, gives the offline
# message and cause 0; a subscriber holding a channel's number, or a missing
# ffmpeg, stops oc-core at start; SIGTERM leaves no fetch behind.
#   test_oc_stream_proc.sh OC_CORE TOOL_OC_CALL DATA_DIR
set -u
OC=$1
CALL=$2
DATA=$3
T=$(mktemp -d /tmp/oc_stream_proc_XXXXXX) || exit 1
PID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
    pkill -f "$T/ffmpeg" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- daemon log"; cat "$T/log" 2>/dev/null; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
fetches() { pgrep -fc "$T/ffmpeg" || true; }

head -c 32 /dev/urandom >"$T/key" && chmod 0400 "$T/key"
echo "the master key" >"$T/secret"
cp "$DATA/clip_10.wav" "$T/offline.wav" # 1.2 s: 10 payloads

# The fake ffmpeg: the URL after -i says what it does; a confinement it can
# get out of makes it exit 3 at once, with no audio (so the call hears the
# offline message, not the stream).
cat >"$T/ffmpeg" <<'EOF'
#!/usr/bin/python3 -I
import socket, sys, time, urllib.parse
url = sys.argv[sys.argv.index("-i") + 1]
u = urllib.parse.urlparse(url)
q = urllib.parse.parse_qs(u.query)
try:
    open(q["secret"][0]).read()
    sys.exit(3)
except PermissionError:
    pass
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sys.exit(3)
except PermissionError:
    pass
out = sys.stdout.buffer
block = b"".join(((3000 if i % 20 < 10 else -3000) & 0xFFFF).to_bytes(2, "little") for i in range(960))
if u.path == "/never":
    time.sleep(60)
elif u.path == "/dies":
    out.write(block * 12)  # 1.44 s at once, then gone
    out.flush()
    sys.exit(1)
else:
    t = time.monotonic()
    while True:
        out.write(block)
        out.flush()
        t += 0.12
        time.sleep(max(0, t - time.monotonic()))
EOF
chmod 0755 "$T/ffmpeg"

conf() { # FFMPEG
cat <<EOF
core_id = 1
key_id = 1
echo = +883160655500100
block = 8831606 1
db = $T/core.db
cell_socket = $T/core.sock
admin_socket = $T/admin.sock
stream = +883160655501021 http://good.test/good?secret=$T/secret $T/offline.wav
stream = +883160655501022 http://dies.test/dies?secret=$T/secret $T/offline.wav
stream = +883160655501023 http://never.test/never?secret=$T/secret $T/offline.wav
stream_ffmpeg = $1
EOF
}
conf "$T/ffmpeg" >"$T/oc-core.conf"
ADM=("$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key")
"$CALL" hss "$T/hss.txt" || fail "tool_oc_call hss"
out=$("${ADM[@]}" import-ocb-hss "$T/hss.txt" 2>&1) || fail "import: $out"
out=$("${ADM[@]}" cell add 1 bench 2>&1) || fail "cell add: $out"
# a channel's number is never a subscriber's (spec §4.1)
out=$("${ADM[@]}" sub add +883160655501021 2>&1) && fail "a channel's number was added as a subscriber: $out"

start() {
    "$OC" --config "$T/oc-core.conf" --key-file "$T/key" 2>>"$T/log" &
    PID=$!
    for _ in $(seq 50); do [ -S "$T/admin.sock" ] && break; sleep 0.1; done
    [ -S "$T/admin.sock" ] || fail "oc-core did not start"
}
stop() { kill "$PID"; wait "$PID"; PID=; }
call() { # CALLED SECONDS -> the tool's output in $T/call
    "$CALL" "$T/core.sock" 1 7 "$1" "$2" >"$T/call"
    echo "$1: $(tr '\n' ' ' <"$T/call")" >&2
}

start
out=$("$OC" admin --socket "$T/admin.sock" status 2>&1) || fail "status: $out"
expect "$out" "stream +883160655501021: idle, 0 listeners"
expect "$out" "stream +883160655501023: idle, 0 listeners"
sleep 1
[ "$(fetches)" = 0 ] || fail "a fetch runs with no call"

# Live: answered once the stream plays, a block every 120 ms, all of it the
# stream (the fake gave audio, so it could neither read the secret nor open
# a Unix socket).
call +883160655501021 4 || fail "the live call: $(cat "$T/call")"
expect "$(cat "$T/call")" "answered"
read -r _ n _ gap <<<"$(grep '^media' "$T/call")"
[ "$n" -ge 20 ] || fail "the live call heard $n payloads in 4 s"
[ "$gap" -lt 300 ] || fail "the live call: a gap of $gap ms"
grep -q "released" "$T/call" && fail "the live call was released: $(cat "$T/call")"
grep -q 'stream 0: first audio after [0-9]* ms' "$T/log" || fail "no first-audio line"
grep -q 'call 00000042: stream sent [0-9]* payloads' "$T/log" || fail "no per-call stream line"
# the tail: still fetching just after, gone 5 s after the hang-up
[ "$(fetches)" = 1 ] || fail "the fetch went at once after the hang-up ($(fetches))"
sleep 6
[ "$(fetches)" = 0 ] || fail "the fetch was not stopped 5 s after the last listener ($(fetches))"
grep -q 'stream 0: closed (no listener)' "$T/log" || fail "no closed line"

# A fetch that dies mid-call: the offline message (10 payloads), cause 0.
call +883160655501022 15
expect "$(cat "$T/call")" "answered"
expect "$(cat "$T/call")" "released cause 0"
grep -q 'stream 1: failed (ffmpeg exited 1)\|stream 1: failed (no audio for 5 s)' "$T/log" ||
    fail "the dying fetch's failure was not logged"
grep -q 'stream sent [0-9]* payloads, skipped [0-9]* (offline message)' "$T/log" || fail "no offline message line"

# A fetch that never gives audio: still ringing at 9 s, the message at 10 s.
t0=$(date +%s)
call +883160655501023 20
expect "$(cat "$T/call")" "answered"
expect "$(cat "$T/call")" "released cause 0"
el=$(( $(date +%s) - t0 ))
[ "$el" -ge 11 ] && [ "$el" -le 16 ] || fail "the never-starting channel took $el s to hang up"
grep -q 'stream 2: failed (no audio in 10 s)' "$T/log" || fail "no 10 s give-up line"
sleep 1
[ "$(fetches)" = 0 ] || fail "a fetch was left after the failures ($(fetches))"

# SIGTERM leaves no fetch: a call up, then a stop.
"$CALL" "$T/core.sock" 1 7 +883160655501021 30 >"$T/call" &
CPID=$!
for _ in $(seq 100); do grep -q answered "$T/call" && break; sleep 0.1; done
[ "$(fetches)" = 1 ] || fail "no fetch during the call"
stop
wait "$CPID" 2>/dev/null
sleep 0.5
[ "$(fetches)" = 0 ] || fail "a fetch outlived oc-core"

# At start: a subscriber with a channel's number, or no ffmpeg, stops it.
out=$("${ADM[@]}" sub add +883160655501234 2>&1) # (already there: the import's)
conf "$T/no-such-ffmpeg" >"$T/oc-core.conf"
"$OC" --config "$T/oc-core.conf" --key-file "$T/key" 2>"$T/log.bad"; rc=$?
[ "$rc" != 0 ] || fail "oc-core started with no ffmpeg"
grep -q 'stream +883160655501021: stream_ffmpeg = .*no-such-ffmpeg' "$T/log.bad" || fail "no ffmpeg: $(cat "$T/log.bad")"
conf "$T/ffmpeg" | sed 's/^stream = +883160655501022 .*/stream = +883160655501234 http:\/\/x.test\/good '"${T//\//\\/}"'\/offline.wav/' \
    >"$T/oc-core.conf"
"$OC" --config "$T/oc-core.conf" --key-file "$T/key" 2>"$T/log.bad"; rc=$?
[ "$rc" != 0 ] || fail "oc-core started with a channel on a subscriber's number"
grep -q 'a subscriber has this number' "$T/log.bad" || fail "subscriber's number: $(cat "$T/log.bad")"
echo PASS
