# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Fetch elfio via FetchContent if not already available
#
# This module provides the elfio library for ELF file manipulation.
# If the consumer already provides an 'elfio' target, we use that.
# Otherwise, we fetch it from GitHub.
#
# Usage:
#   include(cmake/FetchElfio.cmake)
#   # After this, the 'elfio' target is available

include(FetchContent)

if(NOT TARGET elfio)
  # Check if elfio exists in the external directory (legacy submodule support)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/elfio/CMakeLists.txt")
    message(STATUS "Using elfio from external/elfio")
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/external/elfio"
                     "${CMAKE_CURRENT_BINARY_DIR}/elfio" EXCLUDE_FROM_ALL)
  else()
    # Fetch elfio from GitHub
    message(STATUS "Fetching elfio via FetchContent")
    FetchContent_Declare(
      elfio
      GIT_REPOSITORY https://github.com/serge1/ELFIO.git
      GIT_TAG        Release_3.12
      GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(elfio)
  endif()
else()
  message(STATUS "Using existing elfio target provided by consumer")
endif()
