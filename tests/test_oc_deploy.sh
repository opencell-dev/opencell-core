#!/bin/bash
# tools/deploy/oc-deploy (network-core spec §17 decisions 4 and 11), with the
# host side run here (OC_DEPLOY_LOCAL): a toy "opencell-core" with a
# submodule that has its own submodule is deployed at several tags, listed,
# rolled back, and refused anything that is not a tag vX.Y.Z. With a fake
# systemctl (OC_DEPLOY_SYSTEMD=1): restarts, health checks and automatic
# rollback. With fake transports (OC_DEPLOY_SSH): the number of SSH calls,
# what reaches a remote command string, a dropped connection, a script cut
# short. And the default ssh command line, through a fake ssh.
#   test_oc_deploy.sh OC_DEPLOY
# Everything lives in one scratch directory under $TMPDIR, removed on exit;
# no real host, ssh, sudo or systemctl is ever used (fakes on PATH record
# any attempt).
set -u
DEPLOY=$1
[ "$(id -u)" -ne 0 ] || { echo "FAIL: refusing to run as root (a slip would touch the real /usr/local)"; exit 1; }
[ -x "$DEPLOY" ] || { echo "FAIL: deploy script $DEPLOY: No such file or directory"; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/oc_deploy_XXXXXX") || { echo "FAIL: mktemp"; exit 1; }
case "$T" in /?*/oc_deploy_??????) ;; *) echo "FAIL: odd scratch directory '$T'"; exit 1 ;; esac
[ -d "$T" ] && [ ! -L "$T" ] || { echo "FAIL: scratch directory $T"; exit 1; }
cleanup() {
    # A detached "remote" run (the dropped-connection cases) may still be
    # going: wait for its status file, by run id, before removing the tree.
    local id i
    for id in ${WAIT_RUNS:-}; do
        for ((i = 0; i < 100; i++)); do
            [ -f "$R2/var/lib/oc-deploy/status/$id" ] && break
            command -p sleep 0.1
        done
    done
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
refute() { ! grep -q -- "$2" <<<"$1" || fail "did not expect '$2' in: $1"; }
g() { git -c user.name=t -c user.email=t@t -c protocol.file.allow=always "$@"; }
WAIT_RUNS=
R2=$T/root2

# Fakes first on PATH: ssh and sudo record any call and fail (nothing here
# may reach them unless a check says so); systemctl keeps its state in
# $FAKE_SD; sleep returns at once (the host side's health loop; the deploy
# script and this test wait with `command -p sleep`).
mkdir -p "$T/bin" "$T/tmp" "$T/sd"
export TMPDIR=$T/tmp FAKE_SD=$T/sd PATH="$T/bin:$PATH"
cat >"$T/bin/ssh" <<'SH'
#!/bin/bash
printf '%s\n' "$@" >"$FAKE_SD/ssh-args"
cat >/dev/null
exit 255
SH
cat >"$T/bin/sudo" <<'SH'
#!/bin/bash
echo "fake sudo: $*" >>"$FAKE_SD/sudo-called"
exit 1
SH
cat >"$T/bin/sleep" <<'SH'
#!/bin/bash
exit 0
SH
# systemctl for OC_DEPLOY_LOCAL=$FAKE_ROOT: a restart "starts" the build
# current points to as a new PID, whose $FAKE_ROOT/proc/PID/exe is that
# build's binary. restart-fail-for (a tag) makes its restart fail;
# unhealthy-for (a tag) makes the unit inactive while that build runs.
cat >"$T/bin/systemctl" <<'SH'
#!/bin/bash
sd=$FAKE_SD
[ "${1:-}" = -q ] && shift
running() { # the tag of the build the fake process runs
    local pid
    pid=$(cat "$sd/$1.pid" 2>/dev/null) || return 0
    basename "$(dirname "$(dirname "$(readlink "$FAKE_ROOT/proc/$pid/exe")")")"
}
case "$1" in
daemon-reload) echo daemon-reload >>"$sd/calls" ;;
is-enabled) [ "${2:-}" = -q ] && shift; [ -f "$sd/$2.enabled" ] ;;
is-active)
    [ "${2:-}" = -q ] && shift
    [ -f "$sd/$2.pid" ] || exit 3
    [ "$(running "$2")" != "$(cat "$sd/unhealthy-for" 2>/dev/null)" ] || exit 3
    ;;
restart)
    ver=$(basename "$(readlink -f "$FAKE_ROOT/lib/opencell/$2/current")")
    echo "restart $2 $ver" >>"$sd/calls"
    [ "$ver" != "$(cat "$sd/restart-fail-for" 2>/dev/null)" ] || { echo "fake: $2 failed to start" >&2; exit 1; }
    n=$(($(cat "$sd/lastpid" 2>/dev/null || echo 100) + 1))
    echo "$n" >"$sd/lastpid"
    mkdir -p "$FAKE_ROOT/proc/$n"
    ln -sfn "$(readlink -f "$FAKE_ROOT/bin/$2")" "$FAKE_ROOT/proc/$n/exe"
    echo "$n" >"$sd/$2.pid"
    ;;
show) cat "$sd/${*: -1}.pid" 2>/dev/null || echo 0 ;;
*) echo "fake systemctl: $*" >&2; exit 1 ;;
esac
SH
# OC_DEPLOY_SSH shims: "shim HOST COMMAND", the command run here.
#  ssh-shim        runs it; logs each command string to $FAKE_SD/calls-ssh
#                  (one line per call) and SHIM_DELAY delays a deploy's run.
#  ssh-shim-drop   a deploy or rollback run is started detached (after
#                  DROP_DELAY s) and the shim returns 255 at once, as ssh does
#                  when the connection dies while the remote side goes on;
#                  the run's stdout and stderr are a pipe nobody reads, and
#                  0.3 s in, its process group gets SIGHUP.
#  ssh-shim-cut    a deploy or rollback script arrives without its last line.
cat >"$T/bin/ssh-shim" <<'SH'
#!/bin/bash
printf '%s\n' "$2" | tr '\n' ' ' >>"$FAKE_SD/calls-ssh"; echo >>"$FAKE_SD/calls-ssh"
if [ "$2" = "bash -s" ]; then
    s=$(mktemp "$TMPDIR/shim.XXXXXX") || exit 1
    cat >"$s"
    if grep -qE '^OC_ARGS=\(.* (deploy|rollback) ' "$s"; then command -p sleep "${SHIM_DELAY:-0}"; fi
    bash -s <"$s"; rc=$?
    rm -f "$s"
    exit "$rc"
fi
exec bash -c "$2"
SH
cat >"$T/bin/ssh-shim-drop" <<'SH'
#!/bin/bash
echo call >>"$FAKE_SD/calls-drop"
if [ "$2" = "bash -s" ]; then
    s=$(mktemp "$TMPDIR/shim.XXXXXX") || exit 1
    cat >"$s"
    if grep -qE '^OC_ARGS=\(.* (deploy|rollback) ' "$s"; then
        (
            command -p sleep "${DROP_DELAY:-0}"
            { setsid bash -s <"$s" 2>&1 & echo $! >"$s.pid"; } | true
            p=$(cat "$s.pid")
            command -p sleep 0.3
            kill -HUP -- "-$p" 2>/dev/null
            while kill -0 "$p" 2>/dev/null; do command -p sleep 0.1; done
            rm -f "$s" "$s.pid"
        ) >/dev/null 2>&1 </dev/null &
        exit 255
    fi
    bash -s <"$s"; rc=$?
    rm -f "$s"
    exit "$rc"
fi
exec bash -c "$2"
SH
cat >"$T/bin/ssh-shim-cut" <<'SH'
#!/bin/bash
if [ "$2" = "bash -s" ]; then
    s=$(cat)
    if grep -qE '^OC_ARGS=\(.* (deploy|rollback) ' <<<"$s"; then head -n -1 <<<"$s" | bash -s; exit; fi
    bash -s <<<"$s"; exit
fi
exec bash -c "$2"
SH
chmod +x "$T/bin"/*
[ "$(command -v ssh)" = "$T/bin/ssh" ] && [ "$(command -v sudo)" = "$T/bin/sudo" ] || fail "the fake ssh/sudo are not first on PATH"

# ---- a toy opencell-core with nested submodules, tagged ----
mkdir -p "$T/deep" "$T/sub" "$T/top/oc" "$T/top/dist/systemd"
g -C "$T/deep" init -q && echo '#define DEEP 2' >"$T/deep/deep.h" && g -C "$T/deep" add . && g -C "$T/deep" commit -qm deep
g -C "$T/sub" init -q && echo '#define SUB 1' >"$T/sub/sub.h" && g -C "$T/sub" add . && g -C "$T/sub" commit -qm sub
g -C "$T/sub" submodule add -q "$T/deep" deep && g -C "$T/sub" commit -qm "deep in sub"
cd "$T/top" || fail "cd"
g init -q
cat >CMakeLists.txt <<'CM'
cmake_minimum_required(VERSION 3.21)
project(toy C)
add_executable(oc-core oc/oc_core_main.c)
target_include_directories(oc-core PRIVATE third_party/sub third_party/sub/deep)
target_compile_definitions(oc-core PRIVATE OC_VERSION="${OC_VERSION}")
install(TARGETS oc-core RUNTIME DESTINATION bin)
CM
printf '#include <stdio.h>\n#include "sub.h"\n#include "deep.h"\nint main(void) { printf("oc-core %%s %%d\\n", OC_VERSION, SUB + DEEP); return 0; }\n' >oc/oc_core_main.c
printf '[Service]\nExecStart=/usr/local/bin/oc-core\n' >dist/systemd/oc-core.service
g submodule add -q "$T/sub" third_party/sub && g submodule update -q --init --recursive
g add . && g commit -qm one && g tag v0.0.1
sed -i 's/SUB + DEEP/SUB + DEEP + 10/' oc/oc_core_main.c && g commit -qam two && g tag v0.0.2
echo "/* three */" >>oc/oc_core_main.c && g commit -qam three && g tag v0.0.3
# v0.0.4: runs, but `oc-core admin status` does not answer
cp oc/oc_core_main.c "$T/main.good"
printf '#include <stdio.h>\n#include "sub.h"\n#include "deep.h"\nint main(int c, char **v) { (void)v; printf("oc-core %%s %%d\\n", OC_VERSION, SUB + DEEP); return c > 1; }\n' >oc/oc_core_main.c
g commit -qam "admin dead" && g tag v0.0.4
cp "$T/main.good" oc/oc_core_main.c && g commit -qam "good again"
for t in v0.0.5 v0.0.6 v0.0.7 v0.0.8 v0.0.9; do g tag "$t"; done
echo "this is not C" >>oc/oc_core_main.c && g commit -qam broken && g tag v0.1.0
cp "$T/main.good" oc/oc_core_main.c && echo "/* not tagged */" >>oc/oc_core_main.c && g commit -qam untagged
cd / || fail "cd /"

# ---- the host side here, no systemd ----
export OC_DEPLOY_LOCAL=$T/root
D=$T/root/lib/opencell/oc-core
out=$("$DEPLOY" deploy "$T/top" v0.0.1 somehost 2>&1) || fail "deploy v0.0.1: $out"
expect "$out" "oc-core v0.0.1 installed (previous: none)"
expect "$out" "host recorded exit 0"
out=$("$T/root/bin/oc-core") || fail "run v0.0.1"
[ "$out" = "oc-core v0.0.1 3" ] || fail "v0.0.1 runs as: $out" # both submodules were packed
[ -f "$D/v0.0.1/oc-core.service" ] || fail "the unit was not kept with the build"
out=$("$DEPLOY" deploy "$T/top" v0.0.2 somehost 2>&1) || fail "deploy v0.0.2: $out"
expect "$out" "installed (previous: v0.0.1)"
[ "$("$T/root/bin/oc-core")" = "oc-core v0.0.2 13" ] || fail "v0.0.2 is not current"
out=$("$DEPLOY" list somehost oc-core 2>&1)
expect "$out" "v0.0.1 (previous)"
expect "$out" "v0.0.2 (current)"
out=$("$DEPLOY" rollback somehost oc-core 2>&1) || fail "rollback: $out"
expect "$out" "oc-core back to v0.0.1 (previous: v0.0.2)"
[ "$("$T/root/bin/oc-core")" = "oc-core v0.0.1 3" ] || fail "rollback did not take"
# current and previous are never rebuilt in place: rollback is the way back
out=$("$DEPLOY" deploy "$T/top" v0.0.2 somehost 2>&1) && fail "redeployed the previous build: $out"
expect "$out" "oc-deploy rollback somehost oc-core"
out=$("$DEPLOY" deploy "$T/top" v0.0.1 somehost 2>&1) && fail "redeployed the current build: $out"
expect "$out" "v0.0.1 is the current build"
[ "$(readlink "$D/current")" = v0.0.1 ] && [ "$(readlink "$D/previous")" = v0.0.2 ] || fail "a refused deploy moved current/previous"
# from any directory, with a relative REPO_DIR
out=$(cd "$T/top/oc" && "$DEPLOY" deploy .. v0.0.3 somehost 2>&1) || fail "deploy v0.0.3 from a subdirectory: $out"
expect "$out" "installed (previous: v0.0.1)"
[ "$("$T/root/bin/oc-core")" = "oc-core v0.0.3 13" ] || fail "v0.0.3 is not current"
[ "$(find "$D" -mindepth 1 -maxdepth 1 | wc -l)" = 4 ] || fail "not just two builds, current and previous: $(ls -A "$D")"
[ -d "$D/v0.0.1" ] && [ -d "$D/v0.0.3" ] || fail "the wrong builds were kept: $(ls "$D")"
[ -z "$(ls -A "$T/tmp")" ] || fail "uploads or temp files left behind: $(ls -A "$T/tmp")"

# a build that fails leaves everything as it was
out=$("$DEPLOY" deploy "$T/top" v0.1.0 somehost 2>&1) && fail "a broken tag was deployed"
expect "$out" "not C"
expect "$out" "host recorded exit 1"
[ "$(readlink "$D/current")" = v0.0.3 ] && [ "$(readlink "$D/previous")" = v0.0.1 ] || fail "a failed build moved current/previous"
[ "$(ls -A "$D" | tr '\n' ' ')" = "current previous v0.0.1 v0.0.3 " ] || fail "a failed build left: $(ls -A "$D")"
[ -z "$(ls -A "$T/tmp")" ] || fail "a failed build left temp files: $(ls -A "$T/tmp")"

out=$("$DEPLOY" deploy "$T/top" master somehost 2>&1) && fail "a branch was deployed"
expect "$out" "deploys take a tag vX.Y.Z"
out=$("$DEPLOY" deploy "$T/top" v0.1 somehost 2>&1) && fail "v0.1 was deployed"
out=$("$DEPLOY" deploy "$T/top" 'v1.0.0;id' somehost 2>&1) && fail "a tag with a shell word was deployed"
out=$("$DEPLOY" deploy "$T/top" v9.9.9 somehost 2>&1) && fail "a missing tag was deployed"
expect "$out" "has no tag v9.9.9"
out=$("$DEPLOY" deploy "$T/sub" v0.0.1 somehost 2>&1) && fail "a repository that is no program"
out=$("$DEPLOY" deploy "$T/top" v0.0.5 -oProxyCommand=id 2>&1) && fail "a host that is an ssh option"
expect "$out" "not a host name"
out=$("$DEPLOY" list somehost 'oc-core;id' 2>&1) && fail "a program name with a shell word"
expect "$out" "oc-core or oc-cell"
out=$("$DEPLOY" rollback somehost oc-cell 2>&1) && fail "rolled back a program never deployed"
expect "$out" "no previous build of oc-cell"
out=$("$DEPLOY" status somehost 2>&1) || fail "status: $out"
expect "$out" "oc-core: current v0.0.3, previous v0.0.1"
expect "$out" "latest run: .* (exit 1)"
[ ! -e "$FAKE_SD/ssh-args" ] && [ ! -e "$FAKE_SD/sudo-called" ] || fail "ssh or sudo was called in local mode"
[ "$(stat -c %a "$T/root/var/lib/oc-deploy")" = 700 ] || fail "the deploy state is not private"
[ "$(stat -c %a "$T/root/var/lib/oc-deploy/deploy.log")" = 600 ] || fail "the deploy log is not private"
echo "ok   local deploys, rollback, refusals"

# ---- with systemd (the fake): restarts, health, automatic rollback ----
export OC_DEPLOY_LOCAL=$R2 OC_DEPLOY_SYSTEMD=1 FAKE_ROOT=$R2
D=$R2/lib/opencell/oc-core
cur() { readlink "$D/current"; }
prev() { readlink "$D/previous"; }
out=$("$DEPLOY" deploy "$T/top" v0.0.1 somehost 2>&1) || fail "systemd deploy v0.0.1: $out"
expect "$out" "oc-core is not enabled yet: sudo systemctl enable --now oc-core"
cmp -s "$R2/etc/systemd/system/oc-core.service" "$D/v0.0.1/oc-core.service" || fail "the unit was not installed"
grep -q restart "$FAKE_SD/calls" 2>/dev/null && fail "a unit that is not enabled was restarted"
touch "$FAKE_SD/oc-core.enabled"
out=$("$DEPLOY" deploy "$T/top" v0.0.2 somehost 2>&1) || fail "systemd deploy v0.0.2: $out"
expect "$out" "oc-core v0.0.2 is healthy"
expect "$out" "installed (previous: v0.0.1)"
[ "$(tail -2 "$FAKE_SD/calls" | tr '\n' ' ')" = "daemon-reload restart oc-core v0.0.2 " ] || fail "calls: $(cat "$FAKE_SD/calls")"
echo v0.0.3 >"$FAKE_SD/unhealthy-for"
out=$("$DEPLOY" deploy "$T/top" v0.0.3 somehost 2>&1) && fail "an unhealthy build stayed: $out"
expect "$out" "oc-core v0.0.3 is not healthy"
expect "$out" "oc-core back on v0.0.2"
expect "$out" "host recorded exit 1"
[ "$(cur)" = v0.0.2 ] && [ "$(prev)" = v0.0.1 ] && [ ! -e "$D/v0.0.3" ] || fail "after an unhealthy deploy: $(ls -l "$D")"
[ "$(tail -1 "$FAKE_SD/calls")" = "restart oc-core v0.0.2" ] || fail "the old build was not restarted"
rm "$FAKE_SD/unhealthy-for"
echo v0.0.5 >"$FAKE_SD/restart-fail-for"
out=$("$DEPLOY" deploy "$T/top" v0.0.5 somehost 2>&1) && fail "a build that failed to start stayed: $out"
expect "$out" "systemctl restart oc-core failed"
expect "$out" "oc-core back on v0.0.2"
[ "$(cur)" = v0.0.2 ] && [ "$(prev)" = v0.0.1 ] || fail "after a failed restart: $(ls -l "$D")"
rm "$FAKE_SD/restart-fail-for"
out=$("$DEPLOY" deploy "$T/top" v0.0.4 somehost 2>&1) && fail "a core whose admin socket is dead stayed: $out"
expect "$out" "oc-core back on v0.0.2"
[ "$(cur)" = v0.0.2 ] && [ "$(prev)" = v0.0.1 ] || fail "after a dead admin socket: $(ls -l "$D")"
out=$("$DEPLOY" rollback somehost oc-core 2>&1) || fail "systemd rollback: $out"
expect "$out" "oc-core back to v0.0.1 (previous: v0.0.2)"
[ "$(tail -1 "$FAKE_SD/calls")" = "restart oc-core v0.0.1" ] || fail "rollback did not restart"
echo v0.0.2 >"$FAKE_SD/unhealthy-for"
out=$("$DEPLOY" rollback somehost oc-core 2>&1) && fail "rolled back onto an unhealthy build: $out"
expect "$out" "oc-core back on v0.0.1"
[ "$(cur)" = v0.0.1 ] && [ "$(prev)" = v0.0.2 ] || fail "after an unhealthy rollback: $(ls -l "$D")"
rm "$FAKE_SD/unhealthy-for"
echo "ok   systemd: restart, health, automatic rollback"

# ---- the lock, and the directories the host side trusts ----
exec 8>>"$R2/var/lib/oc-deploy/lock"
flock -n 8 || fail "could not take the lock"
latest=$(cat "$R2/var/lib/oc-deploy/latest-run-id")
out=$("$DEPLOY" deploy "$T/top" v0.0.6 somehost 2>&1 8>&-) && fail "deployed while another run held the lock"
expect "$out" "another deploy or rollback is running"
expect "$out" "this run changed nothing"
[ "$(cat "$R2/var/lib/oc-deploy/latest-run-id")" = "$latest" ] || fail "a refused run replaced the latest run id"
out=$("$DEPLOY" status somehost 2>&1 8>&-)
expect "$out" "latest run: $latest (exit 1)"
exec 8>&-
[ "$(cur)" = v0.0.1 ] && [ -z "$(ls -A "$T/tmp")" ] || fail "a refused run changed something: $(ls -A "$T/tmp")"
mkdir "$T/decoy" && chmod 0755 "$T/decoy"
mv "$R2/var/lib/oc-deploy/status" "$T/status.real" && ln -s "$T/decoy" "$R2/var/lib/oc-deploy/status"
out=$("$DEPLOY" deploy "$T/top" v0.0.6 somehost 2>&1) && fail "deployed with a symlinked status directory"
expect "$out" "is a symlink"
[ "$(stat -c %a "$T/decoy")" = 755 ] && [ -z "$(ls -A "$T/decoy")" ] || fail "the symlink's target was touched"
rm "$R2/var/lib/oc-deploy/status" && mv "$T/status.real" "$R2/var/lib/oc-deploy/status"
chmod 0770 "$R2/var/lib/oc-deploy"
out=$("$DEPLOY" rollback somehost oc-core 2>&1) && fail "rolled back with a group-writable state directory"
expect "$out" "group- or other-writable"
chmod 0700 "$R2/var/lib/oc-deploy"
chmod 0775 "$D"
out=$("$DEPLOY" deploy "$T/top" v0.0.6 somehost 2>&1) && fail "deployed into a group-writable build directory"
expect "$out" "group- or other-writable"
chmod 0755 "$D"
[ "$(cur)" = v0.0.1 ] && [ "$(prev)" = v0.0.2 ] || fail "a refused run moved current/previous"
[ -z "$(ls -A "$T/tmp")" ] || fail "refused runs left uploads: $(ls -A "$T/tmp")"
echo "ok   the lock; symlinked or writable directories refused"

# ---- the transport: SSH calls counted; nothing but constants in command strings ----
export OC_DEPLOY_SSH="$T/bin/ssh-shim"
: >"$FAKE_SD/calls-ssh"
out=$("$DEPLOY" deploy "$T/top" v0.0.6 somehost 2>&1) || fail "deploy through the shim: $out"
expect "$out" "installed (previous: v0.0.1)"
n=$(wc -l <"$FAKE_SD/calls-ssh")
[ "$n" -le 3 ] || fail "a quick deploy made $n SSH calls: $(cat "$FAKE_SD/calls-ssh")"
: >"$FAKE_SD/calls-ssh"
out=$("$DEPLOY" list somehost oc-core 2>&1) || fail "list through the shim: $out"
[ "$(wc -l <"$FAKE_SD/calls-ssh")" = 1 ] || fail "list made $(wc -l <"$FAKE_SD/calls-ssh") SSH calls"
# a run that takes 7 s: the live log is fetched every 5 s, not more
: >"$FAKE_SD/calls-ssh"
out=$(SHIM_DELAY=7 "$DEPLOY" deploy "$T/top" v0.0.7 somehost 2>&1) || fail "slow deploy: $out"
n=$(wc -l <"$FAKE_SD/calls-ssh")
[ "$n" -le 4 ] || fail "a 7-second deploy made $n SSH calls: $(cat "$FAKE_SD/calls-ssh")"
[ "$(grep -c "=== run .* start" <<<"$out")" = 1 ] && [ "$(grep -c "installed (previous" <<<"$out")" = 1 ] ||
    fail "the log was not shown once: $out"
[ "$(tail -1 <<<"$out")" = "$(grep "host recorded exit 0" <<<"$out")" ] || fail "the result is not the last line: $out"
grep -q v0 "$FAKE_SD/calls-ssh" && fail "a tag reached a command string: $(cat "$FAKE_SD/calls-ssh")"
[ "$(sort -u "$FAKE_SD/calls-ssh" | wc -l)" = 2 ] || fail "command strings: $(sort -u "$FAKE_SD/calls-ssh")"
echo "ok   one call per step, a live log every 5 s, constant command strings"

# ---- a dropped connection: the run goes on there; the laptop reports its outcome ----
export OC_DEPLOY_SSH="$T/bin/ssh-shim-drop" OC_DEPLOY_POLL_INTERVAL=0.2 OC_DEPLOY_POLL_BUDGET=20
echo v0.0.8 >"$FAKE_SD/unhealthy-for"
out=$("$DEPLOY" deploy "$T/top" v0.0.8 somehost 2>&1) && fail "a dropped unhealthy deploy succeeded: $out"
expect "$out" "ssh exited 255"
expect "$out" "oc-core back on v0.0.7"
expect "$out" "host recorded exit 1"
refute "$out" "re-run"
[ "$(cur)" = v0.0.7 ] && [ "$(prev)" = v0.0.6 ] || fail "after a dropped unhealthy deploy: $(ls -l "$D")"
rm "$FAKE_SD/unhealthy-for"
# the host outlasts the laptop's wait: it says so, and not to run it again
out=$(DROP_DELAY=2 OC_DEPLOY_POLL_BUDGET=1 "$DEPLOY" rollback somehost oc-core 2>&1) && fail "an unknown outcome was a success"
expect "$out" "no status recorded yet"
expect "$out" "oc-deploy status somehost"
expect "$out" "do not just run deploy or rollback again"
refute "$out" "host recorded exit"
id=$(grep -oE '[0-9]{8}T[0-9]{6}Z-[0-9]+' <<<"$out" | head -1)
WAIT_RUNS=$id
for ((i = 0; i < 100; i++)); do [ -f "$R2/var/lib/oc-deploy/status/$id" ] && break; command -p sleep 0.1; done
[ "$(cat "$R2/var/lib/oc-deploy/status/$id" 2>/dev/null)" = 0 ] || fail "the detached rollback did not finish"
[ "$(cur)" = v0.0.6 ] && [ "$(prev)" = v0.0.7 ] || fail "after the detached rollback: $(ls -l "$D")"
unset OC_DEPLOY_POLL_INTERVAL OC_DEPLOY_POLL_BUDGET
# ssh exiting 0 is no proof: a script cut before its last line does nothing
export OC_DEPLOY_SSH="$T/bin/ssh-shim-cut"
out=$("$DEPLOY" deploy "$T/top" v0.0.9 somehost 2>&1) && fail "a cut script was a success: $out"
expect "$out" "recorded no status"
[ "$(cur)" = v0.0.6 ] || fail "a cut script changed current"
echo "ok   dropped connection, unknown outcome, cut script"
unset OC_DEPLOY_SSH OC_DEPLOY_SYSTEMD

# ---- the real transport's command line (a fake ssh records it) ----
unset OC_DEPLOY_LOCAL
mkdir -p "$T/x/short" "$T/x/sym/target" && ln -s "$T/x/sym/target" "$T/x/sym/oc-deploy-ssh"
rm -f "$FAKE_SD/ssh-args"
out=$(cd "$T/x" && XDG_RUNTIME_DIR=short OC_DEPLOY_JUMP=root@147.135.11.61:222 "$DEPLOY" status opencell@10.0.0.60 2>&1) &&
    fail "status through a failing ssh succeeded"
A=$(cat "$FAKE_SD/ssh-args" 2>/dev/null) || fail "ssh was not called: $out"
for want in BatchMode=yes ConnectTimeout=10 ServerAliveInterval=15 ServerAliveCountMax=4 ControlMaster=auto \
    ControlPath=short/oc-deploy-ssh/%C ControlPersist=60 -J root@147.135.11.61:222; do
    grep -qx -- "$want" <<<"$A" || fail "ssh lacks $want: $A"
done
[ "$(tail -3 <<<"$A" | head -2 | tr '\n' ' ')" = "-- opencell@10.0.0.60 " ] || fail "the host is not last: $A"
[ "$(tail -1 <<<"$A")" = 'if [ "$(id -u)" -eq 0 ]; then exec bash -s; else exec sudo -n bash -s; fi' ] ||
    fail "the remote command: $(tail -1 <<<"$A")"
[ "$(stat -c %a "$T/x/short/oc-deploy-ssh")" = 700 ] || fail "the control socket directory is not private"
rm -f "$FAKE_SD/ssh-args"
out=$(cd "$T/x" && XDG_RUNTIME_DIR=short "$DEPLOY" list opencell-bs1 oc-cell 2>&1)
[ "$(tail -1 "$FAKE_SD/ssh-args")" = "bash -s" ] || fail "list is not run plain: $(tail -1 "$FAKE_SD/ssh-args")"
grep -q -- -J "$FAKE_SD/ssh-args" && fail "a jump host without OC_DEPLOY_JUMP"
rm -f "$FAKE_SD/ssh-args"
out=$(cd "$T/x" && XDG_RUNTIME_DIR=sym "$DEPLOY" list opencell-bs1 oc-cell 2>&1) && fail "a symlinked control directory"
expect "$out" "is a symlink"
[ ! -e "$FAKE_SD/ssh-args" ] || fail "ssh was called with a symlinked control directory"
out=$(cd "$T/x" && XDG_RUNTIME_DIR=short "$DEPLOY" deploy "$T/top" v0.0.9 opencell-bs1 2>&1) && fail "a deploy through a failing ssh"
expect "$out" "nothing was changed on opencell-bs1"
grep -qF 'sudo -n true' <<<"$(tail -1 "$FAKE_SD/ssh-args")" || fail "the upload does not check sudo first: $(tail -1 "$FAKE_SD/ssh-args")"
[ ! -e "$FAKE_SD/sudo-called" ] || fail "sudo was called here: $(cat "$FAKE_SD/sudo-called")"
[ -z "$(ls -A "$T/tmp")" ] || fail "temp files left behind: $(ls -A "$T/tmp")"
echo "ok   ssh: multiplexed, jump host, host last, constant commands"
echo "OK"
