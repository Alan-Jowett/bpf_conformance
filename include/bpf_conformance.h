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

typedef enum class _bpf_conformance_test_cpu_version
{
    v1 = 1,
    v2 = 2,
    v3 = 3,
    v4 = 4,
    unknown = -1,
} bpf_conformance_test_cpu_version_t;

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
    default_groups = base32 | base64 | atomic32 | atomic64 | divmul32 | divmul64, // not callx or packet
} bpf_conformance_groups_t;

inline bpf_conformance_groups_t
operator~(bpf_conformance_groups_t a)
{
    return static_cast<bpf_conformance_groups_t>(~static_cast<int>(a));
}

inline bpf_conformance_groups_t
operator|(bpf_conformance_groups_t a, bpf_conformance_groups_t b)
{
    return static_cast<bpf_conformance_groups_t>(static_cast<int>(a) | static_cast<int>(b));
}

inline bpf_conformance_groups_t&
operator|=(bpf_conformance_groups_t& a, bpf_conformance_groups_t b)
{
    return a = a | b;
}

inline bpf_conformance_groups_t
operator&(bpf_conformance_groups_t a, bpf_conformance_groups_t b)
{
    return static_cast<bpf_conformance_groups_t>(static_cast<int>(a) & static_cast<int>(b));
}

inline bpf_conformance_groups_t&
operator&=(bpf_conformance_groups_t& a, bpf_conformance_groups_t b)
{
    return a = a & b;
}

// Add typedef for backwards compatibility.
typedef bpf_conformance_test_cpu_version_t bpf_conformance_test_CPU_version_t;

typedef enum class _bpf_conformance_list_instructions
{
    LIST_INSTRUCTIONS_NONE,   // Do not list instructions.
    LIST_INSTRUCTIONS_USED,   // List instructions used by the test.
    LIST_INSTRUCTIONS_UNUSED, // List instructions not used by the test.
    LIST_INSTRUCTIONS_ALL,    // List all instructions.
} bpf_conformance_list_instructions_t;

typedef struct _bpf_conformance_options
{
    std::optional<std::string> include_test_regex;
    std::optional<std::string> exclude_test_regex;
    bpf_conformance_test_cpu_version_t cpu_version;
    bpf_conformance_groups_t groups;
    bpf_conformance_list_instructions_t list_instructions_option;
    bool debug;
    bool xdp_prolog;
    bool elf_format;
} bpf_conformance_options_t;

/**
 * @brief Run the BPF conformance tests with the given plugin.
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
    options.groups = groups,
    options.list_instructions_option = list_instructions_option;
    options.debug = debug;
    return bpf_conformance_options(test_files, plugin_path, plugin_options, options);
}

const std::string bpf_conformance_xdp_section_name = "xdp";
const std::string bpf_conformance_default_section_name = ".text";
const std::string bpf_conformance_default_function_name = "main";
