#!/bin/bash
# oc-route (OCSS spec 2026-11-01 §3.7): keys, a root table from an NPA CSV
# with pinned and kept indexes, an addition, and show/verify.
set -euo pipefail
TOOL=$1
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

ROOT=$("$TOOL" keygen "$T/root.key")
DEL=$("$TOOL" keygen "$T/del.key")
[ "$(stat -c %a "$T/root.key")" = 600 ] || fail "key mode"
[ "$("$TOOL" pub "$T/root.key")" = "$ROOT" ] || fail "pub"
! "$TOOL" keygen "$T/root.key" 2>/dev/null || fail "keygen overwrote a key"

cat > "$T/npa.csv" <<CSV
# NPA,STATE
865,US-TN
503,US-OR
606,US-KY
201,US-NJ
907,US-AK
416,CA-ON
876,JM
CSV
"$TOOL" make "$T/root.key" "$T/v1.tbl" --version 1 --npa "$T/npa.csv" --core 1=oc-core-1 --core 2=oc-core-2 \
    --east 1 --west 2 --pin 606=1 --pin 503=2 --pin 865=3 --delegate "$DEL" --now 1793500000 >/dev/null
"$TOOL" show "$T/v1.tbl" --root "$ROOT" > "$T/show"
grep -q '^signature ok$' "$T/show" || fail "signature"
grep -q '^block 8831606 1 home 1 secondary 2 tenant 1 epoch 1 state US-KY$' "$T/show" || fail "606"
grep -q '^block 8831503 2 home 2 secondary 1' "$T/show" || fail "503"
grep -q '^block 8831865 3 home 1' "$T/show" || fail "865"
grep -q '^block 8831201 4 home 1' "$T/show" || fail "201 gets 4 (NPA order)"
grep -q '^block 8831416 5 home 1 .* state CA-ON$' "$T/show" || fail "416"
grep -q '^block 8831876 6 home 1 .* state JM$' "$T/show" || fail "876"
grep -q '^block 8831907 7 home 2' "$T/show" || fail "907"
grep -q "^delegate $DEL scope 1 valid 1793500000-1825036000 east core 1 (53 states) west core 2 (34 states)$" "$T/show" ||
    fail "delegation"
! "$TOOL" show "$T/v1.tbl" --root "$DEL" >/dev/null || fail "verified with the wrong key"

# v2: one NPA more, one less; indexes kept, the dropped block kept, the new one above max_idx
grep -v '^201' "$T/npa.csv" > "$T/npa2.csv"
echo '472,US-NC' >> "$T/npa2.csv"
"$TOOL" make "$T/root.key" "$T/v2.tbl" --version 2 --npa "$T/npa2.csv" --core 1=oc-core-1 --core 2=oc-core-2 \
    --east 1 --west 2 --prev "$T/v1.tbl" --floor 7 --revoke "$DEL" 2>"$T/err" >/dev/null
grep -q 'kept 8831201' "$T/err" || fail "kept note"
"$TOOL" show "$T/v2.tbl" --root "$ROOT" > "$T/show2"
grep -q '^block 8831907 7 home 2' "$T/show2" || fail "index kept"
grep -q '^block 8831472 8 home 1' "$T/show2" || fail "new index above max_idx"
grep -q '^block 8831201 4 ' "$T/show2" || fail "dropped block kept"
grep -q "^revoked $DEL$" "$T/show2" || fail "revoked"
! "$TOOL" make "$T/root.key" "$T/v3.tbl" --version 2 --npa "$T/npa2.csv" --core 1=a --core 2=b --east 1 --west 2 \
    --prev "$T/v2.tbl" --floor 8 2>/dev/null || fail "a version not above --prev"
! "$TOOL" make "$T/root.key" "$T/v3.tbl" --version 3 --npa "$T/npa2.csv" --core 1=a --core 2=b --east 1 --west 2 \
    --prev "$T/v2.tbl" 2>/dev/null || fail "--prev without --floor"
echo '999,ZZZZ' > "$T/bad.csv"
! "$TOOL" make "$T/root.key" "$T/bad.tbl" --version 1 --npa "$T/bad.csv" --core 1=a --core 2=b --east 1 --west 2 \
    2>/dev/null || fail "a bad CSV row"

# an addition on v1
"$TOOL" add "$T/del.key" "$T/v1.tbl" "$T/a1.bin" --seq 1 --npa 472,US-NC --npa 945,US-TX --now 1793500000 > "$T/add"
grep -q '^addition 1.1, 2 block(s)$' "$T/add" || fail "add"
"$TOOL" show "$T/a1.bin" --root "$DEL" > "$T/showa"
grep -q '^npa 472 8 state US-NC$' "$T/showa" || fail "first new index is max_idx + 1"
grep -q '^npa 945 9 state US-TX$' "$T/showa" || fail "second"
grep -q '^signature ok$' "$T/showa" || fail "addition signature"
! "$TOOL" show "$T/a1.bin" --root "$ROOT" >/dev/null || fail "an addition verified with a key that did not sign it"
echo PASS
