# The Codec2 vocoder (LGPL-2.1), vendored by tools/codec2/vendor.sh (see
# README.opencell): static, into oc-core (the playback clip's encoder).
# Upstream's own code: its warnings are off, so -Werror can't stop the build.
add_library(codec2 STATIC
    src/codec2.c src/codec2_fft.c src/kiss_fft.c src/kiss_fftr.c src/dump.c src/lpc.c src/nlp.c
    src/postfilter.c src/sine.c src/interp.c src/lsp.c src/mbest.c src/newamp1.c src/phase.c
    src/quantise.c src/pack.c src/codebook.c src/codebookd.c src/codebookjmv.c src/codebookge.c
    src/codebooknewamp1.c src/codebooknewamp1_energy.c)
target_include_directories(codec2 PUBLIC src include)
target_compile_options(codec2 PRIVATE -w)
target_link_libraries(codec2 PUBLIC m)
