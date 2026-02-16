// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This header provides shared type definitions and the executor-based conformance API.
// The main user-facing API with Boost.Process is in include/bpf_conformance.h

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
 * @brief Result of executing a BPF program via an executor.
 */
struct bpf_conformance_plugin_result_t
{
    int exit_code;              ///< Process exit code (0 = success)
    std::string stdout_output;  ///< Plugin stdout
    std::string stderr_output;  ///< Plugin stderr
};

/**
 * @brief Function type for executing BPF bytecode.
 *
 * @param input_data Hex-encoded bytecode to send to plugin stdin.
 * @param args Command line arguments for the plugin.
 * @return Execution result.
 * @throws std::runtime_error if execution fails (e.g., plugin not found).
 */
using bpf_conformance_executor_t = std::function<bpf_conformance_plugin_result_t(
    const std::string& input_data,
    const std::vector<std::string>& args
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
 * @param executor Function to execute the plugin (send data to stdin, return stdout/stderr/exit_code).
 * @param options Options controlling the behavior of the tests.
 * @return Map of test file paths to (result, message) tuples.
 */
std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance_run(
    const std::vector<std::filesystem::path>& test_files,
    bpf_conformance_executor_t executor,
    const bpf_conformance_options_t& options);

// Well-known section/function names
extern const std::string bpf_conformance_xdp_section_name;
extern const std::string bpf_conformance_default_section_name;
extern const std::string bpf_conformance_default_function_name;
