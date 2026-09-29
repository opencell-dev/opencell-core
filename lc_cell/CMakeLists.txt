# lc_cell: a cell's network side as a portable C11 library (network-core
# spec §4.1). oc-cell (plan 8) adds the radio backend and the transport.
add_library(lc_cell STATIC lc_cell.c)
target_include_directories(lc_cell PUBLIC include)
target_link_libraries(lc_cell PUBLIC lc_core lc_sig)
