// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <string>
#include <vector>
#include <iostream>
#include <set>
#include <sstream>

#include <boost/process.hpp>

#include "bpf_test_parser.h"
#include "opcode_names.h"
#include "bpf_conformance.h"

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

std::map<std::filesystem::path, bpf_conformance_test_result_t>
bpf_conformance(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::string& plugin_options,
    bool list_opcodes_tested)
{
    std::set<uint8_t> opcodes_used;
    std::set<uint8_t> opcodes_not_used;
    std::map<std::filesystem::path, bpf_conformance_test_result_t> test_results;

    for (auto& test : test_files) {
        // Parse the test file and extract:
        // Input memory contents - Memory to pass to the BPF program.
        // Expected return value - Expected return value from the BPF program.
        // Expected error string - String returned by BPF runtime if the program fails.
        // BPF instructions - Instructions to pass to the BPF program.
        auto [input_memory, expected_return_value, expected_error_string, byte_code] = parse_test_file(test);

        // It the test file has no BPF instructions, then skip it.
        if (byte_code.size() == 0) {
            test_results[test] = bpf_conformance_test_result_t::TEST_RESULT_SKIP;
            continue;
        }

        for (const auto& inst : byte_code) {
            opcodes_used.insert(inst.opcode);
        }

        std::string return_value_string;
        try {
            // Call the plugin to execute the BPF program.
            boost::process::ipstream output;
            boost::process::opstream input;
            // Pass the input memory to the plugin as arg[1] and any plugin options as arg[2].
            boost::process::child c(
                plugin_path.string(),
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
                test_results[test] = bpf_conformance_test_result_t::TEST_RESULT_ERROR;
                continue;
            }
        } catch (boost::process::process_error& e) {
            std::cout << "Plugin failed to execute test " << test << " with error " << e.what() << std::endl;
            test_results[test] = bpf_conformance_test_result_t::TEST_RESULT_ERROR;
            continue;
        }

        // Parse the return value from the plugin and compare it with the expected return value.
        uint32_t return_value = 0;
        try {
            return_value = std::stoul(return_value_string, nullptr, 16);
        } catch (const std::exception&) {
            std::cout << "Plugin returned invalid return value for test " << test << std::endl;
            test_results[test] = bpf_conformance_test_result_t::TEST_RESULT_ERROR;
            continue;
        }

        if (return_value != (uint32_t)expected_return_value) {
            std::cerr << "Test failure: " << test << std::endl;
            std::cerr << "Expected return value: " << expected_return_value << std::endl;
            std::cerr << "Actual return value: " << return_value << std::endl;
            test_results[test] = bpf_conformance_test_result_t::TEST_RESULT_FAIL;
        } else {
            test_results[test] = bpf_conformance_test_result_t::TEST_RESULT_PASS;
        }
    }

    if (list_opcodes_tested) {
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
    return test_results;
}
