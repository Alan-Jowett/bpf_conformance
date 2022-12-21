// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

typedef enum class _bpf_conformance_test_result
{
    TEST_RESULT_PASS,
    TEST_RESULT_FAIL,
    TEST_RESULT_SKIP,
    TEST_RESULT_ERROR,
    TEST_RESULT_UNKNOWN
} bpf_conformance_test_result_t;

typedef enum class _bpf_conformance_test_CPU_version
{
    v1 = 1,
    v2 = 2,
    v3 = 3,
} bpf_conformance_test_CPU_version_t;

typedef enum class _bpf_conformance_list_instructions
{
    LIST_INSTRUCTIONS_NONE,   // Do not list instructions.
    LIST_INSTRUCTIONS_USED,   // List instructions used by the test.
    LIST_INSTRUCTIONS_UNUSED, // List instructions not used by the test.
    LIST_INSTRUCTIONS_ALL,    // List all instructions.
} bpf_conformance_list_instructions_t;

/**
 * @brief Run the BPF conformance tests with the given plugin.
 *
 * @param[in] test_files List of test files to run.
 * @param[in] plugin_path The path to the plugin to run the tests with.
 * @param[in] plugin_options The options to pass to the plugin.
 * @param[in] include_test_regex A regex that matches the tests to include.
 * @param[in] exclude_test_regex A regex that matches the tests to exclude.
 * @param[in] CPU_version The CPU version to run the tests with.
 * @param[in] list_instructions_option Option controlling which instructions to list.
 * @param[in] debug Print debug information.
 * @return The test results for each test file.
 */
std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    std::optional<std::string> include_test_regex = std::nullopt,
    std::optional<std::string> exclude_test_regex = std::nullopt,
    bpf_conformance_test_CPU_version_t CPU_version = bpf_conformance_test_CPU_version_t::v3,
    bpf_conformance_list_instructions_t list_instructions_option =
        bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_NONE,
    bool debug = false);
