# The Linux side of the core (network core 2): oc_util (logging, config
# files, framed connections: oc-cell uses it too), oc_store (the SQLite
# store with sealed keys and the admin commands) and the oc-core program.
add_library(oc_util STATIC oc_log.c oc_kv.c oc_conn.c)
target_include_directories(oc_util PUBLIC include)
target_link_libraries(oc_util PUBLIC oc_core)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
add_library(oc_store STATIC oc_seal.c oc_sql.c oc_admin.c oc_import.c oc_api.c)
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

add_executable(oc-core oc_core_main.c)
target_compile_definitions(oc-core PRIVATE OC_VERSION="${OC_VERSION}")
target_link_libraries(oc-core PRIVATE oc_store)
if(PROJECT_IS_TOP_LEVEL)
  install(TARGETS oc-core RUNTIME DESTINATION bin)
endif()
