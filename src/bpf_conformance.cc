// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <string>
#include <vector>
#include <iostream>
#include <set>
#include <sstream>

#include <boost/process.hpp>
#include <boost/program_options.hpp>

#include "bpf_test_parser.h"
#include "opcode_names.h"

// This program reads a collection of BPF test programs from the test folder,
// assembles the BPF programs to byte code, calls the plugin to execute the
// BPF programs, and compares the results with the expected results.
// If the test program has memory contents, the program will also pass the
// memory contents to the plugin.

/**
 * @brief Read the list of test files from the provided directory.
 *
 * @param[in] test_file_path Path to the collection of test file.s
 * @return Vector of test files names.
 */
std::vector<std::filesystem::path>
get_test_files(const std::filesystem::path& test_file_path)
{
    std::vector<std::filesystem::path> result;
    for (auto& p : std::filesystem::directory_iterator(test_file_path)) {
        if (p.path().extension() == ".data") {
            result.push_back(p.path());
        }
    }
    return result;
}

/**
 * @brief Convert a vector of bytes to a string of hex bytes.
 *
 * @param[in] data Vector of bytes to convert.
 * @return String of hex bytes.
 */
std::string
base_16_encode(const std::vector<uint8_t>& data)
{
    std::stringstream result;
    for (auto byte : data) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        result << " ";
    }
    return result.str();
}

/**
 * @brief Convert a vector of ebpf instructions to a vector of bytes.
 *
 * @param[in] instructions Intructions to convert.
 * @return Vector of bytes.
 */
std::vector<uint8_t>
ebpf_inst_to_byte_vector(const std::vector<ebpf_inst>& instructions)
{
    std::vector<uint8_t> result;
    for (auto instruction : instructions) {
        uint8_t* instruction_bytes = reinterpret_cast<uint8_t*>(&instruction);
        for (int i = 0; i < sizeof(ebpf_inst); i++) {
            result.push_back(instruction_bytes[i]);
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
            "test_file_path", boost::program_options::value<std::string>(), "Path to test files")(
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

        if (!vm.count("test_file_path")) {
            std::cout << "test_file_path is required" << std::endl;
            return 1;
        }
        if (!vm.count("plugin_path")) {
            std::cout << "plugin_path is required" << std::endl;
            return 1;
        }

        std::string test_file_path = vm["test_file_path"].as<std::string>();
        std::string plugin_path = vm["plugin_path"].as<std::string>();
        std::string plugin_options = vm.count("plugin_options") ? vm["plugin_options"].as<std::string>() : "";

        auto tests = get_test_files(test_file_path);
        std::sort(tests.begin(), tests.end());

        std::map<std::filesystem::path, bool> test_results;

        size_t tests_passed = 0;
        size_t tests_run = 0;

        for (auto& test : tests) {
            // Parse the test file and extract:
            // Input memory contents - Memory to pass to the BPF program.
            // Expected return value - Expected return value from the BPF program.
            // Expected error string - String returned by BPF runtime if the program fails.
            // BPF instructions - Instructions to pass to the BPF program.
            auto [input_memory, expected_return_value, expected_error_string, byte_code] = parse_test_file(test);

            // It the test file has no BPF instructions, then skip it.
            if (byte_code.size() == 0) {
                continue;
            }

            for (const auto& inst : byte_code) {
                opcodes_used.insert(inst.opcode);
            }

            tests_run++;

            // Call the plugin to execute the BPF program.
            boost::process::ipstream output;
            boost::process::opstream input;
            // Pass the input memory to the plugin as arg[1] and any plugin options as arg[2].
            boost::process::child c(
                plugin_path,
                base_16_encode(input_memory),
                plugin_options,
                boost::process::std_out > output,
                boost::process::std_in < input);

            // Pass the BPF instructions to the plugin as stdin.
            input << base_16_encode(ebpf_inst_to_byte_vector(byte_code)) << std::endl;
            input.close();
            std::string line;

            // Read the return value from the plugin from stdout.
            std::string return_value_string;
            while (std::getline(output, line)) {
                return_value_string += line;
            }
            output.close();
            c.wait();

            if (c.exit_code() != 0) {
                std::cout << "Plugin failed to execute test " << test << std::endl;
                test_results[test] = false;
                continue;
            }

            // Parse the return value from the plugin and compare it with the expected return value.
            uint32_t return_value = 0;
            try {
                return_value = std::stoul(return_value_string, nullptr, 16);
            } catch (const std::exception&) {
                std::cout << "Plugin returned invalid return value for test " << test << std::endl;
                test_results[test] = false;
                continue;
            }

            if (return_value != (uint32_t)expected_return_value) {
                std::cerr << "Test failure: " << test << std::endl;
                std::cerr << "Expected return value: " << expected_return_value << std::endl;
                std::cerr << "Actual return value: " << return_value << std::endl;
                test_results[test] = false;
            } else {
                test_results[test] = true;
                tests_passed++;
            }
        }

        // At the end of all the tests, print a summary of the results.
        std::cout << "Test results:" << std::endl;
        for (auto& test : test_results) {
            std::cout << test.first << ": " << (test.second ? "Passed" : "Failed") << std::endl;
        }

        std::cout << "Passed " << tests_passed << " out of " << tests_run << " tests." << std::endl;

        if (vm.count("list_opcodes") && vm["list_opcodes"].as<bool>()) {
            // Compute list of opcodes not used in tests.
            for (auto& opcode : opcodes_from_spec) {
                if (opcodes_used.find(opcode) == opcodes_used.end()) {
                    opcodes_not_used.insert(opcode);
                }
            }

            std::cout << "Opcodes used:" << std::endl;
            for (auto opcode : opcodes_used) {
                std::cout << opcode_to_name(opcode) << std::endl;
            }
            std::cout << "Opcodes not used:" << std::endl;
            for (auto opcode : opcodes_not_used) {
                std::cout << opcode_to_name(opcode) << std::endl;
            }
        }

        return 0;
    } catch (std::filesystem::filesystem_error& e) {
        std::cerr << "Error reading test files: " << e.what() << std::endl;
        return 2;
    } catch (boost::process::process_error& e) {
        std::cerr << "Error running plugin: " << e.what() << std::endl;
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
