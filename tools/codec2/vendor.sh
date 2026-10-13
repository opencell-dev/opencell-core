#!/usr/bin/env bash
# Vendors the Codec2 speech codec (drowe67/codec2, LGPL-2.1) into
# third_party/codec2 at a pinned commit, as the app does
# (opencell-android tools/codec2/vendor.sh): only the vocoder (no FreeDV
# modems), its headers, the codebooks generated from their text sources, a
# version.h, the licence and a note saying what was taken. oc-core encodes
# the playback clip with it (playback clip spec 2026-10-12). Run from
# anywhere; needs git, a host C compiler and network access. Re-running it
# reproduces the same files.
set -euo pipefail
export LC_ALL=C

COMMIT=310777b1c6f1af0bc7c72f5b32f80f6fd9136962 # drowe67/codec2 main, 2026-03-17 (the app's)
REPO=https://github.com/drowe67/codec2.git
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DEST=$ROOT/third_party/codec2
WORK=${XDG_CACHE_HOME:-$HOME/.cache}/opencell-codec2-vendor-core

SOURCES=(codec2.c codec2_fft.c kiss_fft.c kiss_fftr.c dump.c lpc.c nlp.c postfilter.c
         sine.c interp.c lsp.c mbest.c newamp1.c phase.c quantise.c pack.c)
CODEBOOKS=(
  "codebook.c lsp_cb codebook/lsp1.txt codebook/lsp2.txt codebook/lsp3.txt codebook/lsp4.txt codebook/lsp5.txt codebook/lsp6.txt codebook/lsp7.txt codebook/lsp8.txt codebook/lsp9.txt codebook/lsp10.txt"
  "codebookd.c lsp_cbd codebook/dlsp1.txt codebook/dlsp2.txt codebook/dlsp3.txt codebook/dlsp4.txt codebook/dlsp5.txt codebook/dlsp6.txt codebook/dlsp7.txt codebook/dlsp8.txt codebook/dlsp9.txt codebook/dlsp10.txt"
  "codebookjmv.c lsp_cbjmv codebook/lspjmv1.txt codebook/lspjmv2.txt codebook/lspjmv3.txt"
  "codebookge.c ge_cb codebook/gecb.txt"
  "codebooknewamp1.c newamp1vq_cb codebook/train_120_1.txt codebook/train_120_2.txt"
  "codebooknewamp1_energy.c newamp1_energy_cb codebook/newamp1_energy_q.txt"
)

rm -rf "$WORK"
git clone -q --filter=blob:none "$REPO" "$WORK"
git -C "$WORK" checkout -q "$COMMIT"

# Keep our CMakeLists.txt across a re-run.
keep=$(mktemp)
[ -f "$DEST/CMakeLists.txt" ] && cp "$DEST/CMakeLists.txt" "$keep"
rm -rf "$DEST"
mkdir -p "$DEST/src" "$DEST/include/codec2"
[ -s "$keep" ] && cp "$keep" "$DEST/CMakeLists.txt"
rm -f "$keep"
cp "$WORK/COPYING" "$DEST/COPYING"
for f in "${SOURCES[@]}"; do cp "$WORK/src/$f" "$DEST/src/"; done

sed -e 's/@CODEC2_VERSION_MAJOR@/1/' -e 's/@CODEC2_VERSION_MINOR@/2/' \
    -e 's/#cmakedefine CODEC2_VERSION_PATCH @CODEC2_VERSION_PATCH@/#define CODEC2_VERSION_PATCH 0/' \
    -e 's/@CODEC2_VERSION@/1.2.0/' "$WORK/cmake/version.h.in" > "$DEST/include/codec2/version.h"

cc -O2 -o "$WORK/generate_codebook" "$WORK/src/generate_codebook.c" -lm
for spec in "${CODEBOOKS[@]}"; do
  read -r out table inputs <<<"$spec"
  # shellcheck disable=SC2086 # inputs is a list
  (cd "$WORK/src" && "$WORK/generate_codebook" "$table" $inputs) > "$DEST/src/$out"
done

for f in "$DEST"/src/*.c; do
  cc -MM -I"$WORK/src" -I"$DEST/include" "$f"
done | tr ' \\' '\n\n' | grep "^$WORK/src/.*\.h$" | sort -u | while read -r h; do cp "$h" "$DEST/src/"; done

{
  echo "Codec2 vocoder vendored by tools/codec2/vendor.sh. Do not edit: re-run the script."
  echo
  echo "Upstream:  $REPO"
  echo "Commit:    $COMMIT"
  echo "Licence:   GNU LGPL 2.1 (COPYING). oc-core links it statically; this repository"
  echo "           carries the library's full source and build, so oc-core can be"
  echo "           relinked with a modified library (LGPL 2.1 section 6(a))."
  echo "Generated: src/codebook*.c by upstream's generate_codebook from src/codebook/*.txt;"
  echo "           include/codec2/version.h from cmake/version.h.in (1.2.0)."
  echo
  echo "Files:"
  (cd "$DEST" && find . -type f ! -name README.opencell ! -name CMakeLists.txt | sort | sed 's|^\./|  |')
} > "$DEST/README.opencell"

echo "vendored $(find "$DEST" -type f | wc -l) files into $DEST"
