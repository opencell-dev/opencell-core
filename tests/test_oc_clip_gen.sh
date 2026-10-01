#!/bin/bash
# tools/clip/oc-clip-gen (core test services spec §5.2): whole 120 ms
# blocks, 15-30 s, the same bytes twice, a different clip per core; with
# c2enc (OC_C2ENC, or the app build's ~/.cache/codec2-host/src/c2enc) whole
# 18-byte payloads. Skipped (77) where libflite1, numpy or scipy is missing:
# the laptop has them, a core does not need them.
#   test_oc_clip_gen.sh OC_CLIP_GEN
set -u
GEN=$1
python3 -c 'import ctypes, numpy, scipy.signal; ctypes.CDLL("libflite_cmu_us_slt.so.1")' 2>/dev/null ||
    { echo "skipped: libflite1, numpy or scipy missing"; exit 77; }
T=$(mktemp -d /tmp/oc_clip_gen_XXXXXX) || exit 1
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
"$GEN" one "$T/a.raw" >/dev/null || fail "one"
"$GEN" one "$T/b.raw" >/dev/null || fail "one again"
"$GEN" two "$T/c.raw" >/dev/null || fail "two"
"$GEN" five "$T/d.raw" >/dev/null 2>&1 && fail "five was taken"
n=$(stat -c %s "$T/a.raw")
[ $((n % 1920)) = 0 ] || fail "$n bytes: not whole 120 ms blocks"
[ "$n" -ge $((15 * 16000)) ] && [ "$n" -le $((30 * 16000)) ] || fail "$n bytes: not 15-30 s"
cmp -s "$T/a.raw" "$T/b.raw" || fail "the same word gave different bytes"
cmp -s "$T/a.raw" "$T/c.raw" && fail "core one's clip is core two's"
C2ENC=${OC_C2ENC:-$HOME/.cache/codec2-host/src/c2enc}
if [ -x "$C2ENC" ]; then
    "$C2ENC" 1200 "$T/a.raw" "$T/a.bit" || fail "c2enc"
    [ "$(stat -c %s "$T/a.bit")" = $((n / 1920 * 18)) ] || fail "c2enc gave $(stat -c %s "$T/a.bit") bytes"
fi
echo "all passed"
