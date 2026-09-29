# oc_cell: a cell's network side as a portable C11 library (network-core
# spec §4.1). oc-cell (plan 8) adds the radio backend and the transport.
add_library(oc_cell STATIC oc_cell.c)
target_include_directories(oc_cell PUBLIC include)
target_link_libraries(oc_cell PUBLIC oc_core oc_sig)
