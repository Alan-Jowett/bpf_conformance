// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// Re-export core library types
#include <bpf_conformance_core/bpf_conformance.h>

/**
 * @brief Create a BPF executor that uses Boost.Process to run an external plugin.
 *
 * @param plugin_path Path to the plugin executable.
 * @param plugin_options Options to pass to the plugin.
 * @param xdp_prolog Whether XDP prolog is being used (affects ELF section name).
 * @return Executor function compatible with bpf_conformance_run().
 */
bpf_executor_fn
make_process_executor(
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    bool xdp_prolog = false);

/**
 * @brief Run the BPF conformance tests with the given plugin (backwards-compatible API).
 *
 * @param[in] test_files List of test files to run.
 * @param[in] plugin_path The path to the plugin to run the tests with.
 * @param[in] plugin_options The options to pass to the plugin.
 * @param[in] options Options controlling the behavior of the tests.
 * @return The test results for each test file.
 */
std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance_options(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    const bpf_conformance_options_t& options);

// Backwards compatibility wrapper.
/**
 * @brief Run the BPF conformance tests with the given plugin.
 *
 * @param[in] test_files List of test files to run.
 * @param[in] plugin_path The path to the plugin to run the tests with.
 * @param[in] plugin_options The options to pass to the plugin.
 * @param[in] include_test_regex A regex that matches the tests to include.
 * @param[in] exclude_test_regex A regex that matches the tests to exclude.
 * @param[in] cpu_version The CPU version to run the tests with.
 * @param[in] groups The conformance groups to run the tests with.
 * @param[in] list_instructions_option Option controlling which instructions to list.
 * @param[in] debug Print debug information.
 * @return The test results for each test file.
 */
inline std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    std::optional<std::string> include_test_regex = std::nullopt,
    std::optional<std::string> exclude_test_regex = std::nullopt,
    bpf_conformance_test_cpu_version_t cpu_version = bpf_conformance_test_cpu_version_t::v3,
    bpf_conformance_groups_t groups = bpf_conformance_groups_t::default_groups,
    bpf_conformance_list_instructions_t list_instructions_option =
        bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_NONE,
    bool debug = false)
{
    bpf_conformance_options_t options = {};
    options.include_test_regex = include_test_regex;
    options.exclude_test_regex = exclude_test_regex;
    options.cpu_version = cpu_version;
    options.groups = groups;
    options.list_instructions_option = list_instructions_option;
    options.debug = debug;
    return bpf_conformance_options(test_files, plugin_path, plugin_options, options);
}
