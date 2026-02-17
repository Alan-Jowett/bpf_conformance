# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# bpf_conformance_core - Pure C++20 library with optional ELFIO support
# This library provides BPF assembler, disassembler, test file parser,
# and conformance testing functionality.

cmake_minimum_required(VERSION 3.16)

# Allow this to be included as a subdirectory without conflicting with parent project
if(NOT CMAKE_PROJECT_NAME OR CMAKE_PROJECT_NAME STREQUAL "bpf_conformance_core")
  project("bpf_conformance_core" LANGUAGES CXX)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Core sources (no external dependencies)
set(BPF_CONFORMANCE_CORE_SOURCES
  src/bpf_assembler.cc
  src/bpf_disassembler.cc
  src/bpf_test_parser.cc
  src/bpf_conformance.cc
)

# Check for optional ELFIO support
set(BPF_CONFORMANCE_HAS_ELFIO OFF)

# Check if elfio target already exists (parent project may have added it)
if(TARGET elfio)
  set(BPF_CONFORMANCE_HAS_ELFIO ON)
  message(STATUS "bpf_conformance_core: ELFIO found (existing target)")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../external/elfio/CMakeLists.txt")
  # ELFIO available as submodule but not added - let the consumer add it if they want
  message(STATUS "bpf_conformance_core: ELFIO available but not enabled (add elfio target to enable)")
else()
  message(STATUS "bpf_conformance_core: ELFIO not found (bpf_writer will not be available)")
endif()

# Add bpf_writer if ELFIO is available
if(BPF_CONFORMANCE_HAS_ELFIO)
  list(APPEND BPF_CONFORMANCE_CORE_SOURCES src/bpf_writer.cc)
endif()

add_library(bpf_conformance_core STATIC ${BPF_CONFORMANCE_CORE_SOURCES})

target_include_directories(bpf_conformance_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link ELFIO and define macro if available
if(BPF_CONFORMANCE_HAS_ELFIO)
  target_compile_definitions(bpf_conformance_core PUBLIC BPF_CONFORMANCE_HAS_ELFIO)
  target_link_libraries(bpf_conformance_core PRIVATE elfio)
endif()

# Compiler warnings
if(MSVC)
  target_compile_options(bpf_conformance_core PRIVATE /W4)
else()
  target_compile_options(bpf_conformance_core PRIVATE -Wall -Wextra -pedantic)
endif()

# Export the library for use by consumers
add_library(bpf_conformance::core ALIAS bpf_conformance_core)
