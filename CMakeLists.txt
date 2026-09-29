# The OpenCell network core (network-core spec §4.2). Host-only for now: the
# portable libraries oc_core and oc_cell, and their tests. oc_sig comes from
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
if(NOT EXISTS ${OC_FW}/firmware/components/oc_sig/CMakeLists.txt)
  message(FATAL_ERROR "third_party/opencell-firmware is empty: run git submodule update --init")
endif()
add_subdirectory(${OC_FW}/firmware/components/oc_phy oc_phy)
add_subdirectory(${OC_FW}/firmware/components/oc_link oc_link)
add_subdirectory(${OC_FW}/firmware/components/oc_sig oc_sig)
add_subdirectory(oc_core)
add_subdirectory(oc_cell)

enable_testing()
add_subdirectory(tests)
