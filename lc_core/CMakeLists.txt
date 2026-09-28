# lc_core: the network core as a portable C11 library (network-core spec
# §4.2): no OS calls, driven by messages and tick(now). oc-core (network core
# 2) adds SQLite, sockets, TLS and the clock around it.
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c lc_core.c lc_core_hss.c lc_core_reg.c
                           lc_core_switch.c)
target_include_directories(lc_core PUBLIC include)
target_link_libraries(lc_core PUBLIC lc_sig)
