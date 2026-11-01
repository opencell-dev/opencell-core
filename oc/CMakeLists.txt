# The Linux side of the core (network core 2): oc_util (logging, config
# files, framed connections: oc-cell uses it too), oc_store (the SQLite
# store with sealed keys and the admin commands) and the oc-core program.
add_library(oc_util STATIC oc_log.c oc_kv.c oc_conn.c oc_conn_fd.c)
target_include_directories(oc_util PUBLIC include)
target_link_libraries(oc_util PUBLIC oc_core)

# The playback clip (playback clip spec 2026-10-12; OpenVoxNB spec V7): a
# WAV read and encoded at start, with the vendored Codec2 and oc_vox.
add_library(oc_clip STATIC oc_clip.c)
target_include_directories(oc_clip PUBLIC include)
target_link_libraries(oc_clip PUBLIC oc_core PRIVATE codec2 oc_vox)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
add_library(oc_store STATIC oc_seal.c oc_sql.c oc_admin.c oc_import.c oc_api.c oc_rtbl.c)
target_include_directories(oc_store PUBLIC include)
target_link_libraries(oc_store PUBLIC oc_core oc_util oc_phy SQLite::SQLite3 OpenSSL::Crypto)

# The version the programs report: -DOC_VERSION=v1.2.3 (the deploy script
# passes the tag it builds), else what git says about this checkout.
if(NOT OC_VERSION)
  execute_process(COMMAND git describe --tags --always --dirty WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  OUTPUT_VARIABLE OC_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(NOT OC_VERSION)
    set(OC_VERSION unknown)
  endif()
endif()

add_executable(oc-core oc_core_main.c oc_stream.c)
target_compile_definitions(oc-core PRIVATE OC_VERSION="${OC_VERSION}")
target_link_libraries(oc-core PRIVATE oc_store oc_net oc_clip)
if(PROJECT_IS_TOP_LEVEL)
  install(TARGETS oc-core RUNTIME DESTINATION bin)
endif()

# oc-route: the routing authority's laptop tool (OCSS spec 2026-11-01 §3.7);
# built, never installed on a core.
add_executable(oc-route oc_route_tool.c)
target_link_libraries(oc-route PRIVATE oc_store)

# The admin API's TLS (portal plan P4): oc_tls (OpenSSL 3, TLS 1.3, pinned
# peer certificates) and oc_apisrv (its listener and connections); oc_ocss,
# the OCSS links to other cores (core test services spec §6); oc_cellsrv,
# the cells' TLS listener (single-board cell plan A).
add_library(oc_net STATIC oc_tls.c oc_apisrv.c oc_addr.c oc_ocss.c oc_cellsrv.c)
target_include_directories(oc_net PUBLIC include)
target_link_libraries(oc_net PUBLIC oc_store OpenSSL::SSL)
