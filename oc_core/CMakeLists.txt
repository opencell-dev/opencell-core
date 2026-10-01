# oc_core: the network core as a portable C11 library (network-core spec
# §4.2): no OS calls, driven by messages and tick(now). oc-core (network core
# 2) adds SQLite, sockets, TLS and the clock around it.
add_library(oc_core STATIC oc_core_msg.c oc_core_route.c oc_core_mem.c oc_core.c oc_core_hss.c oc_core_reg.c
                           oc_core_switch.c oc_core_peer.c)
target_include_directories(oc_core PUBLIC include)
target_link_libraries(oc_core PUBLIC oc_sig)
