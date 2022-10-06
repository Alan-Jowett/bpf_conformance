# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

project("bpf_conformance")
cmake_minimum_required(VERSION 3.16)

include("cmake/FindLibBpf.cmake")

add_subdirectory("src")

if (LIBBPF_FOUND)
    add_subdirectory("libbpf_plugin")
endif()
