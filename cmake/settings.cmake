# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("bpf_c_settings" INTERFACE)

# Only configure our settings target if we are being built directly.
# If we are being used as a submodule, give a chance to the parent
# project to use the settings they want.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  if(PLATFORM_LINUX OR PLATFORM_MACOS)
    target_compile_options("bpf_c_settings" INTERFACE
      -Wall
      -Werror
      -Iinc
      -O2
      -Wunused-parameter
      -fPIC
    )

    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR
      CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")

      target_compile_options("bpf_c_settings" INTERFACE
        -g  
      )
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
      target_compile_definitions("bpf_c_settings" INTERFACE
        DEBUG
      )
    endif()

    if(BPF_C_ENABLE_COVERAGE)
      target_compile_options("bpf_c_settings" INTERFACE
        -fprofile-arcs
        -ftest-coverage
      )

      target_link_options("bpf_c_settings" INTERFACE
        -fprofile-arcs
      )
    endif()

    if(BPF_C_ENABLE_SANITIZERS)
      set(sanitizer_flags
        -fno-omit-frame-pointer
        -fsanitize=undefined,address
      )

      target_compile_options("bpf_c_settings" INTERFACE
        ${sanitizer_flags}
      )

      target_link_options("bpf_c_settings" INTERFACE
        ${sanitizer_flags}
      )
    endif()

  elseif(PLATFORM_WINDOWS)
    set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION "8.1")

    target_compile_options("bpf_c_settings" INTERFACE
      /W4
    )

    target_compile_definitions("bpf_c_settings" INTERFACE
      UNICODE
      _UNICODE

      $<$<CONFIG:Debug>:DEBUG>
      $<$<CONFIG:Release>:NDEBUG>
      $<$<CONFIG:RelWithDebInfo>:NDEBUG>
    )

  else()
    message(WARNING "BPF Conformance - Unsupported platform")
  endif()
endif()

