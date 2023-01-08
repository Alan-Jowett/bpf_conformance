// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <filesystem>
#include <iostream>
#include <sstream>
#include <boost/program_options.hpp>

#include "../include/bpf_conformance.h"

#if defined(__linux__)
#include <signal.h>

static void
sig_handler(int signo)
{
    if (signo != SIGPIPE) {
        std::cerr << "Received signal " << signo << std::endl;
        exit(1);
    }
}

static void
install_sigpipe_handler()
{
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);
}
#else
static void
install_sigpipe_handler()
{
}
#endif

// This program reads a collection of BPF test programs from the test folder,
// assembles the BPF programs to byte code, calls the plugin to execute the
// BPF programs, and compares the results with the expected results.
// If the test program has memory contents, the program will also pass the
// memory contents to the plugin.

/**
 * @brief Read the list of test files from the provided directory.
 *
 * @param[in] test_file_directory Path to the collection of test files.
 * @return Vector of test files names.
 */
static std::vector<std::filesystem::path>
_get_test_files(const std::filesystem::path& test_file_directory)
{
    std::vector<std::filesystem::path> result;
    for (auto& p : std::filesystem::directory_iterator(test_file_directory)) {
        if (p.path().extension() == ".data") {
            result.push_back(p.path());
        }
    }
    return result;
}

int
main(int argc, char** argv)
{
    // Handle sigpipe handler to avoid crashing when writing to a closed pipe.
    install_sigpipe_handler();

    try {
        boost::program_options::options_description desc("Options");
        desc.add_options()("help", "Print help messages")(
            "test_file_path", boost::program_options::value<std::string>(), "Path to test file")(
            "test_file_directory", boost::program_options::value<std::string>(), "Path to test file directory")(
            "plugin_path", boost::program_options::value<std::string>(), "Path to plugin")(
            "plugin_options", boost::program_options::value<std::string>(), "Options to pass to plugin")(
            "list_instructions", boost::program_options::value<bool>(), "List instructions used and not used in tests")(
            "list_used_instructions", boost::program_options::value<bool>(), "List instructions used in tests")(
            "list_unused_instructions", boost::program_options::value<bool>(), "List instructions not used in tests")(
            "debug", boost::program_options::value<bool>(), "Print debug information")(
            "xdp_prolog", boost::program_options::value<bool>(), "XDP prolog")(
            "elf", boost::program_options::value<bool>(), "ELF format")(
            "cpu_version", boost::program_options::value<std::string>(), "CPU version")(
            "include_regex", boost::program_options::value<std::string>(), "Include regex")(
            "exclude_regex", boost::program_options::value<std::string>(), "Exclude regex");

        boost::program_options::variables_map vm;
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        boost::program_options::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return 1;
        }

        if ((vm.count("test_file_path") == 0) && (vm.count("test_file_directory") == 0)) {
            std::cout << "test_file_path or test_file_directory is required" << std::endl;
            return 1;
        }

        if (!vm.count("plugin_path")) {
            std::cout << "plugin_path is required" << std::endl;
            return 1;
        }

        std::string plugin_path = vm["plugin_path"].as<std::string>();
        std::stringstream plugin_options_stream(vm.count("plugin_options") ? vm["plugin_options"].as<std::string>() : "");

        std::vector<std::string> plugin_options;
        std::string option;
        while (std::getline(plugin_options_stream, option, ' ')) {
            plugin_options.push_back(option);
        }

        // Assume latest version if not specified.
        bpf_conformance_test_cpu_version_t cpu_version = bpf_conformance_test_cpu_version_t::v3;
        if (vm.count("cpu_version")) {
            std::string cpu_version_string = vm["cpu_version"].as<std::string>();
            if (cpu_version_string == "v1") {
                cpu_version = bpf_conformance_test_cpu_version_t::v1;
            } else if (cpu_version_string == "v2") {
                cpu_version = bpf_conformance_test_cpu_version_t::v2;
            } else if (cpu_version_string == "v3") {
                cpu_version = bpf_conformance_test_cpu_version_t::v3;
            } else {
                std::cout << "Invalid CPU version" << std::endl;
                return 1;
            }
        }

        std::optional<std::string> include_regex = vm.count("include_regex") ? std::make_optional(vm["include_regex"].as<std::string>()) : std::nullopt;
        std::optional<std::string> exclude_regex = vm.count("exclude_regex") ? std::make_optional(vm["exclude_regex"].as<std::string>()) : std::nullopt;

        std::vector<std::filesystem::path> tests;
        if (vm.count("test_file_path")) {
            tests.push_back(vm["test_file_path"].as<std::string>());
        } else if (vm.count("test_file_directory")) {
            tests = _get_test_files(vm["test_file_directory"].as<std::string>());
        }
        std::sort(tests.begin(), tests.end());

        size_t tests_passed = 0;
        size_t tests_run = 0;
        bool show_instructions = vm.count("list_instructions") ? vm["list_instructions"].as<bool>() : false;
        bool debug = vm.count("debug") ? vm["debug"].as<bool>() : false;
        bool list_used_instructions = vm.count("list_used_instructions") ? vm["list_used_instructions"].as<bool>() : false;
        bool list_unused_instructions = vm.count("list_unused_instructions") ? vm["list_unused_instructions"].as<bool>() : false;
        bool xdp_prolog = vm.count("xdp_prolog") ? vm["xdp_prolog"].as<bool>() : false;
        bool elf_format = vm.count("elf") ? vm["elf"].as<bool>() : false;
        bpf_conformance_list_instructions_t list_instructions = bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_NONE;
        if (show_instructions) {
            list_instructions = bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_ALL;
        } else if (list_used_instructions) {
            list_instructions = bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_USED;
        } else if (list_unused_instructions) {
            list_instructions = bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_UNUSED;
        }

        bpf_conformance_options_t options;
        options.include_test_regex = include_regex;
        options.exclude_test_regex = exclude_regex;
        options.cpu_version = cpu_version;
        options.list_instructions_option = list_instructions;
        options.debug = debug;
        options.xdp_prolog = xdp_prolog;
        options.elf_format = elf_format;

        std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>> test_results;
        if (options.elf_format == false && options.xdp_prolog == false) {
            test_results = bpf_conformance(tests, plugin_path, plugin_options, include_regex, exclude_regex, cpu_version, list_instructions, debug);
        }
        else {
            test_results = bpf_conformance_options(tests, plugin_path, plugin_options, options);
        }

        // At the end of all the tests, print a summary of the results.
        std::cout << "Test results:" << std::endl;
        for (auto& test : test_results) {
            auto [result, message] = test.second;
            switch (result) {
            case bpf_conformance_test_result_t::TEST_RESULT_PASS:
                std::cout << "PASS: " << test.first << std::endl;
                tests_passed++;
                tests_run++;
                break;
            case bpf_conformance_test_result_t::TEST_RESULT_FAIL:
                std::cout << "FAIL: " << test.first << " " << message << std::endl;
                tests_run++;
                break;
            case bpf_conformance_test_result_t::TEST_RESULT_ERROR:
                std::cout << "ERROR: " << test.first << " " << message << std::endl;
                tests_run++;
                break;
            case bpf_conformance_test_result_t::TEST_RESULT_SKIP:
                std::cout << "SKIP: " << test.first << " " << message << std::endl;
                break;
            case bpf_conformance_test_result_t::TEST_RESULT_UNKNOWN:
                std::cout << "UNKNOWN: " << test.first << " " << message << std::endl;
                break;
            }
        }

        std::cout << "Passed " << tests_passed << " out of " << tests_run << " tests." << std::endl;

        return tests_passed == tests_run ? 0 : 1;
    } catch (std::filesystem::filesystem_error& e) {
        std::cerr << "Error reading test files: " << e.what() << std::endl;
        return 2;
    } catch (std::exception& e) {
        std::cerr << "Unhandled Exception reached the top of main: " << e.what() << ", application will now exit"
                  << std::endl;
        return 2;
    } catch (...) {
        std::cerr << "Unhandled Exception reached the top of main: "
                  << ", application will now exit" << std::endl;
        return 2;
    }
}
