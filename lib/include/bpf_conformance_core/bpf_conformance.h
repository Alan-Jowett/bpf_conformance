// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "ebpf.h"

/**
 * @brief Result of executing a BPF program.
 */
struct bpf_execution_result_t
{
    bool success;               ///< True if execution completed (may still have semantic error)
    int exit_code;              ///< Process/execution exit code (0 = success)
    uint64_t return_value;      ///< Return value (%r0) if successful
    std::string output;         ///< stdout or result output
    std::string error_message;  ///< stderr or error message
};

/**
 * @brief Function type for executing BPF bytecode.
 *
 * Implementations can use any execution strategy: subprocess, in-process VM, etc.
 *
 * @param bytecode The BPF bytecode to execute (raw bytes or ELF depending on elf_format).
 * @param memory Input memory to pass to the BPF program.
 * @param elf_format If true, bytecode is ELF format; if false, raw instruction bytes.
 * @return Execution result including return value or error.
 */
using bpf_executor_fn = std::function<bpf_execution_result_t(
    const std::vector<uint8_t>& bytecode,
    const std::vector<uint8_t>& memory,
    bool elf_format
)>;

/**
 * @brief Test result enumeration.
 */
typedef enum class _bpf_conformance_test_result
{
    TEST_RESULT_PASS,
    TEST_RESULT_FAIL,
    TEST_RESULT_SKIP,
    TEST_RESULT_ERROR,
    TEST_RESULT_UNKNOWN
} bpf_conformance_test_result_t;

/**
 * @brief CPU version for instruction support.
 */
typedef enum class _bpf_conformance_test_cpu_version
{
    v1 = 1,
    v2 = 2,
    v3 = 3,
    v4 = 4,
    unknown = -1,
} bpf_conformance_test_cpu_version_t;

// Backwards compatibility typedef
typedef bpf_conformance_test_cpu_version_t bpf_conformance_test_CPU_version_t;

/**
 * @brief Conformance groups for instruction categories.
 */
typedef enum class _bpf_conformance_groups
{
    none = 0x00000000,
    base32 = 0x00000001,
    base64 = 0x00000002,
    atomic32 = 0x00000004,
    atomic64 = 0x00000008,
    divmul32 = 0x00000010,
    divmul64 = 0x00000020,
    packet = 0x00000040,
    callx = 0x00000080,
    default_groups = base32 | base64 | atomic32 | atomic64 | divmul32 | divmul64,
} bpf_conformance_groups_t;

inline bpf_conformance_groups_t operator~(bpf_conformance_groups_t a)
{
    return static_cast<bpf_conformance_groups_t>(~static_cast<int>(a));
}

inline bpf_conformance_groups_t operator|(bpf_conformance_groups_t a, bpf_conformance_groups_t b)
{
    return static_cast<bpf_conformance_groups_t>(static_cast<int>(a) | static_cast<int>(b));
}

inline bpf_conformance_groups_t& operator|=(bpf_conformance_groups_t& a, bpf_conformance_groups_t b)
{
    return a = a | b;
}

inline bpf_conformance_groups_t operator&(bpf_conformance_groups_t a, bpf_conformance_groups_t b)
{
    return static_cast<bpf_conformance_groups_t>(static_cast<int>(a) & static_cast<int>(b));
}

inline bpf_conformance_groups_t& operator&=(bpf_conformance_groups_t& a, bpf_conformance_groups_t b)
{
    return a = a & b;
}

/**
 * @brief Options for listing instructions.
 */
typedef enum class _bpf_conformance_list_instructions
{
    LIST_INSTRUCTIONS_NONE,
    LIST_INSTRUCTIONS_USED,
    LIST_INSTRUCTIONS_UNUSED,
    LIST_INSTRUCTIONS_ALL,
} bpf_conformance_list_instructions_t;

/**
 * @brief Options for conformance testing.
 */
typedef struct _bpf_conformance_options
{
    std::optional<std::string> include_test_regex;
    std::optional<std::string> exclude_test_regex;
    bpf_conformance_test_cpu_version_t cpu_version = bpf_conformance_test_cpu_version_t::v3;
    bpf_conformance_groups_t groups = bpf_conformance_groups_t::default_groups;
    bpf_conformance_list_instructions_t list_instructions_option = bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_NONE;
    bool debug = false;
    bool xdp_prolog = false;
    bool elf_format = false;
} bpf_conformance_options_t;

/**
 * @brief Run BPF conformance tests using a custom executor.
 *
 * This is the core conformance testing function that accepts any executor implementation.
 *
 * @param test_files List of test files to run.
 * @param executor Function to execute BPF bytecode.
 * @param options Options controlling the behavior of the tests.
 * @return Map of test file paths to (result, message) tuples.
 */
std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance_run(
    const std::vector<std::filesystem::path>& test_files,
    bpf_executor_fn executor,
    const bpf_conformance_options_t& options);

// Well-known section/function names
const std::string bpf_conformance_xdp_section_name = "xdp";
const std::string bpf_conformance_default_section_name = ".text";
const std::string bpf_conformance_default_function_name = "main";
