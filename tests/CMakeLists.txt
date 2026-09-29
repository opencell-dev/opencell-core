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
oc_test(test_core_reg oc_core)
oc_test(test_net_sim oc_cell)
oc_test(test_oc_conn oc_util)
oc_test(test_oc_seal oc_store)
