#!/bin/bash
# tools/clip/oc-clip-gen (core test services spec §5.2): an 8 kHz mono
# 16-bit WAV of whole 120 ms blocks, 15-30 s, a different clip per core.
# Skipped (77) where piper (OC_PIPER), its voice (OC_PIPER_MODEL), numpy or
# scipy is missing: the laptop has them, a core does not need them. Piper
# samples noise, so two runs need not give the same bytes.
#   test_oc_clip_gen.sh OC_CLIP_GEN
set -u
GEN=$1
python3 -c 'import numpy, scipy.signal' 2>/dev/null && command -v "${OC_PIPER:-piper}" >/dev/null &&
    [ -f "${OC_PIPER_MODEL:-$HOME/.cache/opencell-piper/en_US-lessac-medium.onnx}" ] ||
    { echo "skipped: piper, its voice, numpy or scipy missing"; exit 77; }
T=$(mktemp -d /tmp/oc_clip_gen_XXXXXX) || exit 1
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
"$GEN" one "$T/a.wav" >/dev/null || fail "one"
"$GEN" two "$T/c.wav" >/dev/null || fail "two"
"$GEN" five "$T/d.wav" >/dev/null 2>&1 && fail "five was taken"
python3 -I - "$T/a.wav" <<'EOF2' || fail "a.wav is not the WAV oc-core wants"
import sys, wave
w = wave.open(sys.argv[1])
assert (w.getnchannels(), w.getsampwidth(), w.getframerate()) == (1, 2, 8000), w.getparams()
n = w.getnframes()
assert n % 960 == 0, f"{n} samples: not whole 120 ms blocks"
assert 15 * 8000 <= n <= 30 * 8000, f"{n / 8000:.2f} s: not 15-30 s"
EOF2
cmp -s "$T/a.wav" "$T/c.wav" && fail "core one's clip is core two's"
"$GEN" say "The stream is offline." "$T/s.wav" >/dev/null || fail "say" # a stream's offline message
"$GEN" say "" "$T/e.wav" >/dev/null 2>&1 && fail "say with no text was taken"
echo "all passed"
