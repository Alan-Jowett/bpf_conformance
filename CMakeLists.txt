# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)
project("bpf_conformance")

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

include("cmake/FindLibBpf.cmake")
include(CTest)

add_subdirectory("src")
if (EXISTS "${PROJECT_SOURCE_DIR}/external/elfio")
add_subdirectory("external/elfio")
else()
message(FATAL_ERROR "Missing elfio -- initialize submodules recursively, please.")
endif()

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
