# Host tests (Unity), one executable per tests/<name>.c.
include(FetchContent)
FetchContent_Declare(unity
  GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
  GIT_TAG v2.6.1)
FetchContent_MakeAvailable(unity)

function(lc_test name lib)
  add_executable(${name} ${name}.c)
  target_link_libraries(${name} PRIVATE ${lib} unity)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

lc_test(test_core_msg lc_core)
