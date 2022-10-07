# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  find_package(Boost REQUIRED)
  find_package(Boost_program_options REQUIRED)
  find_package(boost_filesystem REQUIRED)
  set(CMAKE_CXX_STANDARD 20)
  set(PLATFORM_LIB pthread boost_program_options boost_filesystem)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  find_program(NUGET nuget)
  if (NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
  else ()
    exec_program(${NUGET} ARGS install "Boost" -Version 1.80.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_filesystem-vc142" -Version 1.80.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_program_options-vc142" -Version 1.80.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
  endif()
  set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)
  set(Boost_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/packages/boost_filesystem-vc142/lib/native ${CMAKE_BINARY_DIR}/packages/boost_program_options-vc142/lib/native)
endif ()

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

add_executable(
  bpf_conformance
  bpf_assembler.cc
  bpf_test_parser.cc
  bpf_conformance.cc
)

# Required for the ebpf_inst type
target_include_directories("bpf_conformance" PRIVATE
  "${CMAKE_SOURCE_DIR}/vm"
  "${Boost_INCLUDE_DIRS}"
)


target_link_libraries(bpf_conformance PRIVATE ${PLATFORM_LIB})