// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <filesystem>
#include <iostream>
#include <boost/program_options.hpp>

#include "../include/bpf_conformance.h"

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
std::vector<std::filesystem::path>
get_test_files(const std::filesystem::path& test_file_directory)
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
    try {
        std::set<uint8_t> opcodes_used;
        std::set<uint8_t> opcodes_not_used;

        boost::program_options::options_description desc("Options");
        desc.add_options()("help", "Print help messages")(
            "test_file_path", boost::program_options::value<std::string>(), "Path to test file")(
            "test_file_directory", boost::program_options::value<std::string>(), "Path to test file directory")(
            "plugin_path", boost::program_options::value<std::string>(), "Path to plugin")(
            "plugin_options", boost::program_options::value<std::string>(), "Options to pass to plugin")(
            "list_opcodes", boost::program_options::value<bool>(), "List opcodes used in tests");

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
        std::string plugin_options = vm.count("plugin_options") ? vm["plugin_options"].as<std::string>() : "";

        std::vector<std::filesystem::path> tests;
        if (vm.count("test_file_path")) {
            tests.push_back(vm["test_file_path"].as<std::string>());
        } else if (vm.count("test_file_directory")) {
            tests = get_test_files(vm["test_file_directory"].as<std::string>());
        }
        std::sort(tests.begin(), tests.end());

        size_t tests_passed = 0;
        size_t tests_run = 0;
        auto test_results = bpf_conformance(tests, plugin_path, plugin_options, vm.count("list_opcodes"));

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

        return 0;
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
