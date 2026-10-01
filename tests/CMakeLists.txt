# Host tests (Unity), one executable per tests/<name>.c.
include(FetchContent)
FetchContent_Declare(unity
  GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
  GIT_TAG v2.6.1)
FetchContent_MakeAvailable(unity)

function(oc_test name lib)
  add_executable(${name} ${name}.c)
  target_link_libraries(${name} PRIVATE ${lib} unity)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

oc_test(test_core_msg oc_core)
oc_test(test_core_route oc_core)
oc_test(test_core_store oc_core)
oc_test(test_core_link oc_core)
oc_test(test_core_hss oc_core)
target_include_directories(test_core_hss PRIVATE ${CMAKE_SOURCE_DIR}/oc_core)
oc_test(test_core_switch oc_core)
oc_test(test_core_play oc_core)
oc_test(test_core_reg oc_core)
oc_test(test_net_sim oc_cell)
oc_test(test_oc_conn oc_util)
oc_test(test_oc_seal oc_store)
oc_test(test_oc_sql oc_store)
oc_test(test_oc_admin oc_store)
oc_test(test_oc_api oc_store)

# oc-core as a process, with a bare cell (tool_oc_hello) to speak HELLO, a
# cell with a terminal in a call (tool_oc_call) and a slow admin peer
# (tool_oc_drip).
add_executable(tool_oc_hello tool_oc_hello.c)
target_link_libraries(tool_oc_hello PRIVATE oc_util)
add_executable(tool_oc_call tool_oc_call.c)
target_link_libraries(tool_oc_call PRIVATE oc_util)
add_executable(tool_oc_drip tool_oc_drip.c)
target_link_libraries(tool_oc_drip PRIVATE oc_util)
add_test(NAME test_oc_core_proc
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_oc_core_proc.sh $<TARGET_FILE:oc-core> $<TARGET_FILE:tool_oc_hello>
                 $<TARGET_FILE:tool_oc_drip> $<TARGET_FILE:tool_oc_call>)

# tools/deploy/oc-deploy with its host side run here (OC_DEPLOY_LOCAL) on a
# toy repository; fake ssh, sudo and systemctl.
add_test(NAME test_oc_deploy COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_oc_deploy.sh ${PROJECT_SOURCE_DIR}/tools/deploy/oc-deploy)

# tools/ca/oc-ca, and the test PKI (build/pki) the TLS tests use.
add_test(NAME test_oc_ca COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_oc_ca.sh ${PROJECT_SOURCE_DIR}/tools/ca/oc-ca
                                 ${CMAKE_BINARY_DIR}/pki)
set_tests_properties(test_oc_ca PROPERTIES FIXTURES_SETUP pki)
add_executable(test_oc_tls test_oc_tls.c)
target_link_libraries(test_oc_tls PRIVATE oc_net unity)
add_test(NAME test_oc_tls COMMAND test_oc_tls ${CMAKE_BINARY_DIR}/pki)
set_tests_properties(test_oc_tls PROPERTIES FIXTURES_REQUIRED pki)

# oc-core's admin API as a process, with a TLS client (tool_oc_api) and a
# bare cell beside it.
add_executable(tool_oc_api tool_oc_api.c)
target_link_libraries(tool_oc_api PRIVATE oc_net)
add_test(NAME test_oc_api_proc
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_oc_api_proc.sh $<TARGET_FILE:oc-core> $<TARGET_FILE:tool_oc_api>
                 $<TARGET_FILE:tool_oc_hello> ${CMAKE_BINARY_DIR}/pki)
set_tests_properties(test_oc_api_proc PROPERTIES FIXTURES_REQUIRED pki)
