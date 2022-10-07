# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

include_directories(${LIBBPF_INCLUDE_DIRS})
link_directories(${LIBBPF_LIBRARIES})

add_executable(
  libbpf_plugin
  libbpf_plugin.cc
)

target_link_libraries(libbpf_plugin PRIVATE ${LIBBPF_LIBRARIES})



