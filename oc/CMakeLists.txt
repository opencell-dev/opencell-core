# The Linux side of the core (network core 2): oc_util (logging, config
# files, framed connections: oc-cell uses it too), oc_store (the SQLite
# store with sealed keys and the admin commands) and the oc-core program.
add_library(oc_util STATIC oc_log.c oc_kv.c oc_conn.c)
target_include_directories(oc_util PUBLIC include)
target_link_libraries(oc_util PUBLIC oc_core)
