# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# This file is derived from the following link:
# https://github.com/iovisor/bpftrace/blob/master/cmake/FindLibBpf.cmake

# - Try to find libbpf
# Once done this will define
#
#  LIBBPF_FOUND - system has libbpf with required version
#  LibBpf_FOUND - same as LIBBPF_FOUND (for find_package compatibility)
#  LIBBPF_INCLUDE_DIRS - the libbpf include directory
#  LIBBPF_LIBRARIES - Link these to use libbpf
#  LIBBPF_DEFINITIONS - Compiler switches required for using libbpf
#  LIBBPF_VERSION_STRING - the version of libbpf found

# Minimum required version for bpf_conformance
# Required APIs: bpf_prog_load, bpf_program__set_insns, libbpf_register_prog_handler
set(LIBBPF_MINIMUM_VERSION "1.0.0")

find_path (LIBBPF_INCLUDE_DIRS
  NAMES
    bpf/bpf.h
    bpf/libbpf.h
  PATHS
    ENV CPATH)

find_library (LIBBPF_LIBRARIES
  NAMES
    bpf
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

# Try to find the version from libbpf_version.h
set(_LIBBPF_VERSION_OK FALSE)
if (LIBBPF_INCLUDE_DIRS AND LIBBPF_LIBRARIES)
  if (EXISTS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h")
    file(STRINGS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h" LIBBPF_MAJOR_VERSION_LINE
         REGEX "^#define[ \t]+LIBBPF_MAJOR_VERSION[ \t]+[0-9]+")
    file(STRINGS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h" LIBBPF_MINOR_VERSION_LINE
         REGEX "^#define[ \t]+LIBBPF_MINOR_VERSION[ \t]+[0-9]+")
    file(STRINGS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h" LIBBPF_PATCH_VERSION_LINE
         REGEX "^#define[ \t]+LIBBPF_PATCH_VERSION[ \t]+[0-9]+")

    if (LIBBPF_MAJOR_VERSION_LINE AND LIBBPF_MINOR_VERSION_LINE)
      string(REGEX REPLACE "^#define[ \t]+LIBBPF_MAJOR_VERSION[ \t]+([0-9]+).*" "\\1"
             LIBBPF_MAJOR_VERSION "${LIBBPF_MAJOR_VERSION_LINE}")
      string(REGEX REPLACE "^#define[ \t]+LIBBPF_MINOR_VERSION[ \t]+([0-9]+).*" "\\1"
             LIBBPF_MINOR_VERSION "${LIBBPF_MINOR_VERSION_LINE}")
      if (LIBBPF_PATCH_VERSION_LINE)
        string(REGEX REPLACE "^#define[ \t]+LIBBPF_PATCH_VERSION[ \t]+([0-9]+).*" "\\1"
               LIBBPF_PATCH_VERSION "${LIBBPF_PATCH_VERSION_LINE}")
      else()
        set(LIBBPF_PATCH_VERSION "0")
      endif()
      set(LIBBPF_VERSION_STRING "${LIBBPF_MAJOR_VERSION}.${LIBBPF_MINOR_VERSION}.${LIBBPF_PATCH_VERSION}")

      # Check version meets minimum requirement
      if (NOT LIBBPF_VERSION_STRING VERSION_LESS LIBBPF_MINIMUM_VERSION)
        set(_LIBBPF_VERSION_OK TRUE)
      else()
        message(WARNING "libbpf version ${LIBBPF_VERSION_STRING} found, but ${LIBBPF_MINIMUM_VERSION} or higher is required. "
                        "Some Linux distributions have older versions; consider building from source: https://github.com/libbpf/libbpf")
      endif()
    endif()
  else()
    message(WARNING "Could not determine libbpf version (libbpf_version.h not found). "
                    "Minimum required version is ${LIBBPF_MINIMUM_VERSION}.")
  endif()
endif()

# Clear the variables if version check failed so FIND_PACKAGE_HANDLE_STANDARD_ARGS reports correctly
if (NOT _LIBBPF_VERSION_OK)
  set(LIBBPF_LIBRARIES LIBBPF_LIBRARIES-NOTFOUND)
  set(LIBBPF_INCLUDE_DIRS LIBBPF_INCLUDE_DIRS-NOTFOUND)
endif()

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBpf
  REQUIRED_VARS LIBBPF_LIBRARIES LIBBPF_INCLUDE_DIRS
  VERSION_VAR LIBBPF_VERSION_STRING)

mark_as_advanced (LIBBPF_LIBRARIES LIBBPF_INCLUDE_DIRS LIBBPF_VERSION_STRING)

# Sync both variable names for compatibility
set(LIBBPF_FOUND ${LibBpf_FOUND})

if (LIBBPF_FOUND)
  set (LIBBPF_DEFINITIONS -DHAVE_LIBBPF)
  message(STATUS "Found libbpf version ${LIBBPF_VERSION_STRING}")
endif()