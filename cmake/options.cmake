# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

if(PLATFORM_LINUX OR PLATFORM_MACOS)
  option(BPF_C_ENABLE_COVERAGE "Set to true to enable coverage flags")
  option(BPF_C_ENABLE_SANITIZERS "Set to true to enable the address and undefined sanitizers")
endif()

# Note that the compile_commands.json file is only exporter when
# using the Ninja or Makefile generator
set(CMAKE_EXPORT_COMPILE_COMMANDS true CACHE BOOL "Set to true to generate the compile_commands.json file (forced on)" FORCE)