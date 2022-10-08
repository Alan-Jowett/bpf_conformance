# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(PLATFORM_WINDOWS true)

elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(PLATFORM_MACOS true)

elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(PLATFORM_LINUX true)
endif()
