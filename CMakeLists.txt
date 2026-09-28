# The OpenCell network core (network-core spec §4.2). Host-only for now: the
# portable libraries lc_core and lc_cell, and their tests. lc_sig comes from
# the firmware repository (third_party/opencell-firmware, a submodule pinned
# to a firmware commit) and is built here by the firmware's own host
# CMakeLists (the OpenSSL backend), under this project's flags. It is never
# copied into this repository.
cmake_minimum_required(VERSION 3.16)
project(opencell_core C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror)

set(OC_FW ${CMAKE_CURRENT_SOURCE_DIR}/third_party/opencell-firmware)
if(NOT EXISTS ${OC_FW}/firmware/components/lc_sig/CMakeLists.txt)
  message(FATAL_ERROR "third_party/opencell-firmware is empty: run git submodule update --init")
endif()
add_subdirectory(${OC_FW}/firmware/components/lc_phy lc_phy)
add_subdirectory(${OC_FW}/firmware/components/lc_link lc_link)
add_subdirectory(${OC_FW}/firmware/components/lc_sig lc_sig)

enable_testing()
add_subdirectory(tests)
