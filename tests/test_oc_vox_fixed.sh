#!/bin/bash
# oc-core's oc_vox is the fixed-point production code only (codec
# negotiation ruling R10): no float reference (oc_vox_ref_*) and no libm
# call in the library. This is the only guard, so it fails when nm itself
# fails or lists nothing, rather than passing on an empty pipe.
#   test_oc_vox_fixed.sh LIBOC_VOX.a
set -u
LIB=$1
SYMS=$(nm "$LIB" 2>&1) || { echo "FAIL: nm $LIB failed: $SYMS"; exit 1; }
if ! grep -q ' oc_vox_[a-z_0-9]*' <<<"$SYMS"; then
    echo "FAIL: nm listed no oc_vox symbols in $LIB"
    exit 1
fi
rc=0
if grep ' oc_vox_ref_' <<<"$SYMS"; then
    echo "FAIL: the float reference (oc_vox_ref_*) is in $LIB"
    rc=1
fi
if grep -E ' U (sin|cos|tan|atan|atan2|sqrt|exp|exp2|log|log2|log10|pow)[fl]?$' <<<"$SYMS"; then
    echo "FAIL: $LIB calls libm"
    rc=1
fi
exit $rc
