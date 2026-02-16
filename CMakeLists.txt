# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)
project("bpf_conformance")

# Option to build the tools (requires Boost and ELFIO)
option(BPF_CONFORMANCE_BUILD_TOOLS "Build conformance runner and CLI tools (requires Boost and ELFIO)" ON)

if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
  # Install Git pre-commit hook
  file(COPY scripts/pre-commit scripts/commit-msg
       DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
endif ()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  add_compile_options(/ZH:SHA_256 /guard:cf /Qspectre /sdl)
  add_link_options(/guard:cf /CETCOMPAT)
endif()

# Add ELFIO early if building tools (so lib/ can detect it for optional bpf_writer)
if(BPF_CONFORMANCE_BUILD_TOOLS)
  if(NOT TARGET elfio)
    if(EXISTS "${PROJECT_SOURCE_DIR}/external/elfio/CMakeLists.txt")
      add_subdirectory("${PROJECT_SOURCE_DIR}/external/elfio"
                       "${CMAKE_BINARY_DIR}/elfio" EXCLUDE_FROM_ALL)
    else()
      message(FATAL_ERROR "elfio not found. Run 'git submodule update --init --recursive'")
    endif()
  endif()
endif()

# Always build the core library (no external dependencies, unless ELFIO is available)
add_subdirectory("lib")

# Optionally build tools (requires Boost and ELFIO)
if(BPF_CONFORMANCE_BUILD_TOOLS)
  include("cmake/FindLibBpf.cmake")
  include(CTest)

  add_subdirectory("tools")

  file(COPY tests DESTINATION .)

  if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    file(COPY Docker/Windows/Dockerfile DESTINATION .)
  endif()

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(COPY Docker/Linux/Dockerfile DESTINATION .)
  endif()

  if (LIBBPF_FOUND)
      add_subdirectory("libbpf_plugin")
  endif()
endif()
