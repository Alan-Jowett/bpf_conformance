// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <filesystem>
#include <map>
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

/**
 * @brief Run the BPF conformance tests with the given plugin.
 *
 * @param[in] test_files List of test files to run.
 * @param[in] plugin_path The path to the plugin to run the tests with.
 * @param[in] plugin_options The options to pass to the plugin.
 * @param[in] list_opcodes_tested Print the opcodes tested.
 * @return The test results for each test file.
 */
std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    bpf_conformance_test_CPU_version_t CPU_version = bpf_conformance_test_CPU_version_t::v3,
    bool list_opcodes_tested = false,
    bool debug = false);
