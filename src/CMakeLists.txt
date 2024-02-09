# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
  "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  find_package(Boost REQUIRED COMPONENTS program_options filesystem)
  set(PLATFORM_LIB pthread "${Boost_LIBRARIES}")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  find_program(NUGET nuget)

  if("${BOOST_VERSION}" STREQUAL "")
    set(BOOST_VERSION "1.80.0")
  endif()

  if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio 17 2022")
    set(MSVC_PLATFORM "143")
  elseif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio 16 2019")
    set(MSVC_PLATFORM "142")
  else()
    message("ERROR: Unsupported Visual Studio version")
  endif()

  if(NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
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

add_library("bpf_conformance"
  bpf_assembler.cc
  bpf_test_parser.cc
  bpf_conformance.cc
  bpf_writer.cc
)

add_executable(
  bpf_conformance_runner
  runner.cc
)

add_dependencies(bpf_conformance elfio)

target_include_directories("bpf_conformance" PRIVATE
  "${Boost_INCLUDE_DIRS}"
  "${PROJECT_SOURCE_DIR}/include"
  elfio
)

target_include_directories("bpf_conformance_runner" PRIVATE
  "${Boost_INCLUDE_DIRS}"
  "${PROJECT_SOURCE_DIR}/include"
)

target_link_directories(bpf_conformance PRIVATE elfio)
target_link_libraries(bpf_conformance PRIVATE ${PLATFORM_LIB} elfio)
target_link_libraries(bpf_conformance_runner PRIVATE ${PLATFORM_LIB} "bpf_conformance")

if(MSVC)
  target_compile_options(bpf_conformance PRIVATE /W4)
  target_compile_options(bpf_conformance_runner PRIVATE /W4)
else()
  target_compile_options(bpf_conformance PRIVATE -Wall -Wextra -pedantic)
  target_compile_options(bpf_conformance_runner PRIVATE -Wall -Wextra -pedantic)
endif()

find_program(ECHO echo)

enable_testing()

add_test(
  NAME cpu_v1
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_directory ${PROJECT_BINARY_DIR}/tests --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --cpu_version v1 --exclude_regex "imm-" --exclude_groups callx
)

add_test(
  NAME cpu_v2
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_directory ${PROJECT_BINARY_DIR}/tests --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --cpu_version v2 --exclude_regex "imm-" --exclude_groups callx
)

add_test(
  NAME cpu_v3
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_directory ${PROJECT_BINARY_DIR}/tests --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --cpu_version v3 --debug true --list_instructions true --exclude_regex "imm-" --exclude_groups callx
)

add_test(
  NAME elf_format
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_directory ${PROJECT_BINARY_DIR}/tests --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --cpu_version v3 --debug true --list_instructions true --elf true --exclude_regex "(call_local*|imm-)" --exclude_groups callx
)

add_test(
  NAME no_bpf_bytecode
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_SOURCE_DIR}/negative/empty.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --cpu_version v3 --debug true --exclude_groups callx
)

set_tests_properties(
  no_bpf_bytecode
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Test file has no BPF instructions"
)

add_test(
  NAME invalid_return_value
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_BINARY_DIR}/tests/add.data --plugin_path ${ECHO} --plugin_options "Hello World" --debug true
)

set_tests_properties(
  invalid_return_value
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Plugin return value could not be parsed.*(.*Hello World.*)"
)

add_test(
  NAME wrong_output
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_BINARY_DIR}/tests/add.data --plugin_path ${ECHO} --plugin_options "1" --debug true
)

set_tests_properties(
  wrong_output
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Plugin returned incorrect return value 1 expected 3"
)

add_test(
  NAME invalid_plugin_name
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_BINARY_DIR}/tests/add.data --debug true --plugin_path unknown_command 2>log.txt || cat log.txt
)

set_tests_properties(
  invalid_plugin_name
  PROPERTIES
  PASS_REGULAR_EXPRESSION "failed to execute test"
)

add_test(
  NAME plugin_failed
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_BINARY_DIR}/tests/add.data --plugin_path ${PROJECT_SOURCE_DIR}/negative/invalid.sh --plugin_options "2"
)

set_tests_properties(
  plugin_failed
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Plugin returned error code 2"
)

add_test(
  NAME wrong_error
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/error.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin
)

set_tests_properties(
  wrong_error
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Plugin returned error code 1 and output  but expected Invalid"
)

add_test(
  NAME expect_failure
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/error.data --plugin_path ${PROJECT_SOURCE_DIR}/negative/invalid.sh
)

set_tests_properties(
  expect_failure
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Plugin return value could not be parsed.*(.*This is a negative test.*)"
)

add_test(
  NAME verifier_failure
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/error.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  verifier_failure
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Plugin returned error code 1 and output Failed to load program"
)

add_test(
  NAME invalid_register
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_register.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  invalid_register
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Invalid register: %r50"
)

add_test(
  NAME invalid_offset
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_offset.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  invalid_offset
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Failed to decode register and offset: %r1"
)

add_test(
  NAME invalid_operand_count
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_operand_count.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  invalid_operand_count
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Invalid number of operands for mnemonic: lddw"
)

add_test(
  NAME invalid_label
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_label.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  invalid_label
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Invalid label: NOT_A_LABEL"
)

add_test(
  NAME invalid_mnemonic
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_mnemonic.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  invalid_mnemonic
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Invalid mnemonic: ldxq"
)

add_test(
  NAME libbpf_plugin_usage
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --help 2>&1
)

set_tests_properties(
  libbpf_plugin_usage
  PROPERTIES
  PASS_REGULAR_EXPRESSION "usage:"
)

add_test(
  NAME invalid_lock
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_lock.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug" 2>&1
)

set_tests_properties(
  invalid_lock
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Invalid number of operands"
)

add_test(
  NAME invalid_lock2
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_lock2.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
  )

set_tests_properties(
  invalid_lock2
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Invalid number of operands for lock"
)

add_test(
  NAME include_test
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/tests/lock_add.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug" --include_regex lock
)

set_tests_properties(
  include_test
  PROPERTIES
  PASS_REGULAR_EXPRESSION "PASS"
)

add_test(
  NAME exclude_test
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/tests/lock_add.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug" --exclude_regex lock
)

set_tests_properties(
  exclude_test
  PROPERTIES
  PASS_REGULAR_EXPRESSION "SKIP"
)

add_test(
  NAME negative_include_test
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/tests/lock_add.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug" --include_regex clock
)

set_tests_properties(
  negative_include_test
  PROPERTIES
  PASS_REGULAR_EXPRESSION "SKIP"
)

add_test(
  NAME negative_exclude_test
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/tests/lock_add.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug" --exclude_regex clock
)

add_test(
  NAME usage
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --help
)

set_tests_properties(
  usage
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Options:"
)

add_test(
  NAME missing_test_path
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner
)

set_tests_properties(
  missing_test_path
  PROPERTIES
  PASS_REGULAR_EXPRESSION "test_file_path or test_file_directory"
)

add_test(
  NAME missing_plugin_path
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_SOURCE_DIR}/tests/lock_add.data
)

set_tests_properties(
  missing_plugin_path
  PROPERTIES
  PASS_REGULAR_EXPRESSION "plugin_path is required"
)

add_test(
  NAME invalid_cpu_version
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_SOURCE_DIR}/tests/lock_add.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --cpu_version not_a_version
)

set_tests_properties(
  invalid_cpu_version
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Invalid CPU version"
)

add_test(
  NAME invalid_test_directory
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_directory not_a_directory --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin
)

set_tests_properties(
  invalid_test_directory
  PROPERTIES
  PASS_REGULAR_EXPRESSION "No such file or directory"
)

add_test(
  NAME fail_with_error
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_SOURCE_DIR}/tests/add.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--help" --debug true
)

set_tests_properties(
  fail_with_error
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Plugin returned error code 1 and output"
)

add_test(
  NAME unknown_directive
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --debug true --test_file_path ${PROJECT_SOURCE_DIR}/negative/invalid_unknown_directive.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  unknown_directive
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Test file has no BPF instructions."
)

add_test(
  NAME libbpf_program_bytes
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --program "b4  00  00  00  00  00  00  00 95  00  00  00  00  00  00  00"
  )

set_tests_properties(
  libbpf_program_bytes
  PROPERTIES
  PASS_REGULAR_EXPRESSION "0"
)

add_test(
  NAME invalid_option
  COMMAND ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --not_an_option 2>&1
  )

set_tests_properties(
  invalid_option
  PROPERTIES
  PASS_REGULAR_EXPRESSION "unrecognised option"
)

add_test(
  NAME list_used_instructions
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_directory ${PROJECT_BINARY_DIR}/tests --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --xdp_prolog true --cpu_version v1 --list_used_instructions true
)

set_tests_properties(
  list_used_instructions
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Instructions used by tests"
)

add_test(
  NAME list_unused_instructions
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_directory ${PROJECT_BINARY_DIR}/tests --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --cpu_version v1 --list_unused_instructions true
)

set_tests_properties(
  list_unused_instructions
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Instructions not used by tests"
)

add_test(
  NAME back_compat
  COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_BINARY_DIR}/tests/add.data --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin
)

add_test(
  NAME incorrect_return_value_high_bits
	COMMAND sudo ${PROJECT_BINARY_DIR}/bin/bpf_conformance_runner --test_file_path ${PROJECT_SOURCE_DIR}/negative/incorrect_return_value_high_bits.data  --plugin_path ${PROJECT_BINARY_DIR}/bin/libbpf_plugin --cpu_version v1 --xdp_prolog true --plugin_options "--debug"
)

set_tests_properties(
  incorrect_return_value_high_bits
  PROPERTIES
  PASS_REGULAR_EXPRESSION "incorrect return value.*9905498421827150353"
)
