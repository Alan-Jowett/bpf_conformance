# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

project("bpf_conformance")
cmake_minimum_required(VERSION 3.16)

if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
  # Install Git pre-commit hook
  file(COPY scripts/pre-commit scripts/commit-msg
       DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
endif ()

include("cmake/FindLibBpf.cmake")

add_subdirectory("src")

if (LIBBPF_FOUND)
    add_subdirectory("libbpf_plugin")
endif()
