# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# bpf_conformance tools - Requires Boost and ELFIO dependencies
# This builds the conformance runner, assembler CLI, disassembler CLI, and the
# bpf_conformance library (with process execution capabilities).
#
# NOTE: ELFIO is expected to be added by the root CMakeLists.txt before this file.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find/setup Boost
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
   "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  find_package(Boost REQUIRED COMPONENTS program_options filesystem)
  set(PLATFORM_LIB pthread "${Boost_LIBRARIES}")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  find_program(NUGET nuget)

  if("${BOOST_VERSION}" STREQUAL "")
    set(BOOST_VERSION "1.87.0")
  endif()

  if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio 17 2022")
    set(MSVC_PLATFORM "143")
  elseif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio 16 2019")
    set(MSVC_PLATFORM "142")
  else()
    message(FATAL_ERROR
      "Unsupported Visual Studio version: ${CMAKE_GENERATOR}\n"
      "Supported versions:\n"
      "  - Visual Studio 17 2022 (vc143)\n"
      "  - Visual Studio 16 2019 (vc142)\n"
      "Use: cmake -G \"Visual Studio 17 2022\" ...")
  endif()

  if(NOT NUGET)
    message(FATAL_ERROR
      "NuGet not found. Install from https://www.nuget.org/downloads\n"
      "Then ensure nuget.exe is in your PATH")
  else()
    exec_program(${NUGET} ARGS install "Boost" -Version ${BOOST_VERSION} -ExcludeVersion -OutputDirectory ${PROJECT_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_filesystem-vc${MSVC_PLATFORM}" -Version ${BOOST_VERSION} -ExcludeVersion -OutputDirectory ${PROJECT_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_program_options-vc${MSVC_PLATFORM}" -Version ${BOOST_VERSION} -ExcludeVersion -OutputDirectory ${PROJECT_BINARY_DIR}/packages)
  endif()

  set(Boost_INCLUDE_DIRS ${PROJECT_BINARY_DIR}/packages/boost/lib/native/include)
  set(Boost_LIBRARY_DIRS ${PROJECT_BINARY_DIR}/packages/boost_filesystem-vc${MSVC_PLATFORM}/lib/native ${PROJECT_BINARY_DIR}/packages/boost_program_options-vc${MSVC_PLATFORM}/lib/native)
endif()

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

# bpf_conformance library (with Boost process execution)
# Note: bpf_writer is now in bpf_conformance_core (conditionally compiled with ELFIO)
add_library(bpf_conformance STATIC
  bpf_conformance_process.cc
)

add_dependencies(bpf_conformance bpf_conformance_core)

target_include_directories(bpf_conformance
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
  PRIVATE
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(bpf_conformance PUBLIC bpf_conformance_core PRIVATE ${PLATFORM_LIB})

# Conformance runner executable
add_executable(bpf_conformance_runner
  runner.cc
)

target_include_directories(bpf_conformance_runner PRIVATE
  ${Boost_INCLUDE_DIRS}
  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(bpf_conformance_runner PRIVATE ${PLATFORM_LIB} bpf_conformance)

# Disassembler CLI
add_executable(bpf_disasm
  bpf_disasm.cc
)

target_include_directories(bpf_disasm PRIVATE
  ${Boost_INCLUDE_DIRS}
)

target_link_libraries(bpf_disasm PRIVATE ${PLATFORM_LIB} bpf_conformance_core)

# Assembler CLI
add_executable(bpf_asm
  bpf_asm.cc
)

target_include_directories(bpf_asm PRIVATE
  ${Boost_INCLUDE_DIRS}
)

target_link_libraries(bpf_asm PRIVATE ${PLATFORM_LIB} bpf_conformance_core)

# Compiler warnings
if(MSVC)
  target_compile_options(bpf_conformance PRIVATE /W4)
  target_compile_options(bpf_conformance_runner PRIVATE /W4)
  target_compile_options(bpf_disasm PRIVATE /W4)
  target_compile_options(bpf_asm PRIVATE /W4)
else()
  target_compile_options(bpf_conformance PRIVATE -Wall -Wextra -pedantic)
  target_compile_options(bpf_conformance_runner PRIVATE -Wall -Wextra -pedantic)
  target_compile_options(bpf_disasm PRIVATE -Wall -Wextra -pedantic)
  target_compile_options(bpf_asm PRIVATE -Wall -Wextra -pedantic)
endif()

# Include test definitions
include(${CMAKE_CURRENT_SOURCE_DIR}/tests.cmake)
