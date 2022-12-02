# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

include_directories(${LIBBPF_INCLUDE_DIRS})
link_directories(${LIBBPF_LIBRARIES})

include(CheckSymbolExists)

set(CMAKE_REQUIRED_INCLUDES ${LIBBPF_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${LIBBPF_LIBRARIES})
check_symbol_exists(bpf_prog_load "bpf/bpf.h" HAS_BPF_PROG_LOAD)

if(NOT HAS_BPF_PROG_LOAD)
  add_compile_definitions(USE_DEPRECATED_LOAD_PROGRAM)
endif()

add_executable(
  libbpf_plugin
  libbpf_plugin.cc
)

target_link_libraries(libbpf_plugin PRIVATE ${LIBBPF_LIBRARIES})



