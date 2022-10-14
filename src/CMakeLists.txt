# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  find_package(Boost REQUIRED COMPONENTS program_options filesystem)
  set(PLATFORM_LIB pthread "${Boost_LIBRARIES}")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  find_program(NUGET nuget)
  if ("${BOOST_VERSION}" STREQUAL "")
    set(BOOST_VERSION "1.80.0")
  endif()
  if (NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
  else ()
    exec_program(${NUGET} ARGS install "Boost" -Version ${BOOST_VERSION} -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_filesystem-vc142" -Version ${BOOST_VERSION} -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_program_options-vc142" -Version ${BOOST_VERSION} -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
  endif()
  set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)
  set(Boost_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/packages/boost_filesystem-vc142/lib/native ${CMAKE_BINARY_DIR}/packages/boost_program_options-vc142/lib/native)
endif ()

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

add_library("bpf_conformance"
  bpf_assembler.cc
  bpf_test_parser.cc
  bpf_conformance.cc
)

add_executable(
  bpf_conformance_runner
  runner.cc
)

target_include_directories("bpf_conformance" PRIVATE
  "${Boost_INCLUDE_DIRS}"
  "${CMAKE_SOURCE_DIR}/include"
)

target_include_directories("bpf_conformance_runner" PRIVATE
  "${Boost_INCLUDE_DIRS}"
  "${CMAKE_SOURCE_DIR}/include"
)

target_link_libraries(bpf_conformance PRIVATE ${PLATFORM_LIB})
target_link_libraries(bpf_conformance_runner PRIVATE ${PLATFORM_LIB} "bpf_conformance")

find_program(ECHO echo)

enable_testing()

add_test(
  NAME bpf_conformance_v1
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_directory ${CMAKE_BINARY_DIR}/tests --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --cpu_version v1
)

add_test(
  NAME bpf_conformance_v2
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_directory ${CMAKE_BINARY_DIR}/tests --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --cpu_version v2
)

add_test(
  NAME bpf_conformance_v3
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_directory ${CMAKE_BINARY_DIR}/tests --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --cpu_version v3 --debug true --list_opcodes true
)

add_test(
  NAME no_bpf_bytecode
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/empty.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin
)

set_tests_properties(
  no_bpf_bytecode
  PROPERTIES
  PASS_REGULAR_EXPRESSION "Test file has no BPF instructions"
)

add_test(
  NAME invalid_return_value
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_BINARY_DIR}/tests/add.data --plugin_path ${ECHO} --plugin_options "Hello World"
)

set_tests_properties(
  invalid_return_value
  PROPERTIES
  WILL_FAIL true
  PASS_REGULAR_EXPRESSION "Plugin returned invalid return value Hello World"
)

add_test(
  NAME wrong_output
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_BINARY_DIR}/tests/add.data --plugin_path ${ECHO} --plugin_options "1"
)

set_tests_properties(
  wrong_output
  PROPERTIES
  WILL_FAIL true
  PASS_REGULAR_EXPRESSION "Plugin returned incorrect return value 1 expected 3"
)

add_test(
  NAME invalid_plugin_name
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_BINARY_DIR}/tests/add.data --plugin_path unknown_command 2>log.txt || cat log.txt
)

set_tests_properties(
  invalid_plugin_name
  PROPERTIES
  PASS_REGULAR_EXPRESSION "failed to execute test"
)

add_test(
  NAME plugin_failed
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_BINARY_DIR}/tests/add.data --plugin_path "$(which ls)" --plugin_options "unknown_file" 2>log.txt
)

set_tests_properties(
  plugin_failed
  PROPERTIES
  WILL_FAIL true
  PASS_REGULAR_EXPRESSION "Plugin returned error code 2"
)

add_test(
  NAME wrong_error
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/error.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin
)

set_tests_properties(
  wrong_error
  PROPERTIES
  WILL_FAIL true
  PASS_REGULAR_EXPRESSION "Plugin returned error code and output but expected Invalid"
)

add_test(
  NAME expect_failure
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/error.data --plugin_path ${CMAKE_SOURCE_DIR}/negative/invalid.sh
)

set_tests_properties(
  expect_failure
  PROPERTIES
  WILL_FAIL true
  PASS_REGULAR_EXPRESSION "Plugin returned error code 1 and output but expected Invalid"
)

add_test(
  NAME verifier_failure
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/error.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --plugin_options "--debug"
  )

set_tests_properties(
  verifier_failure
  PROPERTIES
  WILL_FAIL true
  FAIL_REGULAR_EXPRESSION "Plugin returned error code 1 and output Failed to load program"
)

add_test(
  NAME invalid_register
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/invalid_register.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --plugin_options "--debug"
  )

set_tests_properties(
  invalid_register
  PROPERTIES
  WILL_FAIL true
  FAIL_REGULAR_EXPRESSION "Invalid register: r50"
)

add_test(
  NAME invalid_offset
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/invalid_offset.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --plugin_options "--debug"
  )

set_tests_properties(
  invalid_offset
  PROPERTIES
  WILL_FAIL true
  FAIL_REGULAR_EXPRESSION "Failed to decode register and offset: r1"
)

add_test(
  NAME invalid_operand_count
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/invalid_operand_count.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --plugin_options "--debug"
  )

set_tests_properties(
  invalid_operand_count
  PROPERTIES
  WILL_FAIL true
  FAIL_REGULAR_EXPRESSION "Invalid number of operands for mnemonic: lddw"
)

add_test(
  NAME invalid_label
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/invalid_label.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --plugin_options "--debug"
  )

set_tests_properties(
  invalid_label
  PROPERTIES
  WILL_FAIL true
  FAIL_REGULAR_EXPRESSION "Invalid label: NOT_A_LABEL"
)

add_test(
  NAME invalid_mnemonic
  COMMAND sudo ${CMAKE_BINARY_DIR}/src/bpf_conformance_runner --test_file_path ${CMAKE_SOURCE_DIR}/negative/invalid_mnemonic.data --plugin_path ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --plugin_options "--debug"
  )

set_tests_properties(
  invalid_mnemonic
  PROPERTIES
  WILL_FAIL true
  FAIL_REGULAR_EXPRESSION "Invalid mnemonic: ldxq"
)


add_test(
  NAME libbpf_plugin_usage
  COMMAND sudo ${CMAKE_BINARY_DIR}/libbpf_plugin/libbpf_plugin --help
  )

set_tests_properties(
  libbpf_plugin_usage
  PROPERTIES
  WILL_FAIL true
  FAIL_REGULAR_EXPRESSION "usage: libbpf_plugin"
)
