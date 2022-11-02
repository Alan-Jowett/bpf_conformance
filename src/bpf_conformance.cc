// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <boost/process.hpp>

#include <iostream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "bpf_test_parser.h"
#include "opcode_names.h"
#include "../include/bpf_conformance.h"

/**
 * @brief Convert a vector of bytes to a string of hex bytes.
 *
 * @param[in] data Vector of bytes to convert.
 * @return String of hex bytes.
 */
std::string
_base_16_encode(const std::vector<uint8_t>& data)
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
 * @param[in] instructions Instructions to convert.
 * @return Vector of bytes.
 */
std::vector<uint8_t>
_ebpf_inst_to_byte_vector(const std::vector<ebpf_inst>& instructions)
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

void
log_debug_result(
    std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>> test_results,
    const std::filesystem::path& test)
{
    auto [result, message] = test_results[test];
    switch (result) {
    case bpf_conformance_test_result_t::TEST_RESULT_PASS:
        std::cout << "Test " << test << " succeeded" << std::endl;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_FAIL:
        std::cout << "Test " << test << " failed: " << message << std::endl;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_SKIP:
        std::cout << "Test " << test << " skipped: " << message << std::endl;
        break;
    case bpf_conformance_test_result_t::TEST_RESULT_ERROR:
        std::cout << "Test " << test << " error: " << message << std::endl;
        break;
    }
}

std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    std::optional<std::string> include_test_regex,
    std::optional<std::string> exclude_test_regex,
    bpf_conformance_test_CPU_version_t CPU_version,
    bool list_opcodes_tested,
    bool debug)
{
    std::set<uint8_t> opcodes_used;
    std::set<uint8_t> opcodes_not_used;
    std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>> test_results;

    for (auto& test : test_files) {
        // Parse the test file and extract:
        // Input memory contents - Memory to pass to the BPF program.
        // Expected return value - Expected return value from the BPF program.
        // Expected error string - String returned by BPF runtime if the program fails.
        // BPF instructions - Instructions to pass to the BPF program.
        auto [input_memory, expected_return_value, expected_error_string, byte_code] = parse_test_file(test);

        if (include_test_regex.has_value()) {
            std::regex include_regex(include_test_regex.value_or(""));
            if (!std::regex_search(test.filename().string(), include_regex)) {
                test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Skipped by include regex."};
                continue;
            }
        }

        if (exclude_test_regex.has_value()) {
            std::regex exclude_regex(exclude_test_regex.value_or(""));
            if (std::regex_search(test.filename().string(), exclude_regex)) {
                test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Skipped by exclude regex."};
                continue;
            }
        }

        // It the test file has no BPF instructions, then skip it.
        if (byte_code.size() == 0) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Test file has no BPF instructions."};
            log_debug_result(test_results, test);
            continue;
        }

        bpf_conformance_test_CPU_version_t required_cpu_version = bpf_conformance_test_CPU_version_t::v1;

        // Determine the required CPU version for the test.
        for (size_t i = 0; i < byte_code.size(); i++) {
            auto inst = byte_code[i];
            // If this is an atomic store, then the test requires CPU version 3.
            if (((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_STX) &&
                (((inst.opcode & EBPF_MODE_ATOMIC) == EBPF_MODE_ATOMIC))) {
                required_cpu_version = std::max(required_cpu_version, bpf_conformance_test_CPU_version_t::v3);
            }
            // If this is a EBPF_CLS_JMP32, then we know this is v3.
            else if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP32) {
                required_cpu_version = std::max(required_cpu_version, bpf_conformance_test_CPU_version_t::v3);
            } else if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP) {
                // If this is a EBPF_CLS_JMP, then check if it is a less than operation.
                if ((inst.opcode & EBPF_ALU_OP_MASK) >= (EBPF_OP_JLT_IMM & EBPF_ALU_OP_MASK)) {
                    // It his is a less than operation, then we know this is v2.
                    required_cpu_version = std::max(required_cpu_version, bpf_conformance_test_CPU_version_t::v2);
                }
            }
            if (inst.opcode == EBPF_OP_LDDW) {
                // Instruction has a 64-bit immediate and takes two instructions slots.
                i++;
            }
        }

        // If the test requires a CPU version that is not supported by the current CPU version, then skip the test.
        if (required_cpu_version > CPU_version) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Test file contains unsupported instructions."};
            log_debug_result(test_results, test);
            continue;
        }

        for (const auto& inst : byte_code) {
            opcodes_used.insert(inst.opcode);
        }

        // If caller requested debug output, then print the test file name, input memory, and BPF instructions.
        if (debug) {
            std::cerr << "Test file: " << test << std::endl;
            std::cerr << "Input memory: " << _base_16_encode(input_memory) << std::endl;
            std::cerr << "Expected return value: " << expected_return_value << std::endl;
            std::cerr << "Expected error string: " << expected_error_string << std::endl;
            std::cerr << "Byte code: " << _base_16_encode(_ebpf_inst_to_byte_vector(byte_code)) << std::endl;
        }

        std::string return_value_string;
        std::string error_string;
        try {
            // Call the plugin to execute the BPF program.
            boost::process::ipstream output;
            boost::process::ipstream error;
            boost::process::opstream input;
            std::optional<boost::process::child> child;

            if (input_memory.size() > 0) {
                 child = std::make_optional<boost::process::child>(
                    plugin_path.string(),
                    _base_16_encode(input_memory),
                    boost::process::args(plugin_options),
                    boost::process::std_out > output,
                    boost::process::std_in<input, boost::process::std_err> error);
            }
            else {
                 child = std::make_optional<boost::process::child>(
                    plugin_path.string(),
                    boost::process::args(plugin_options),
                    boost::process::std_out > output,
                    boost::process::std_in<input, boost::process::std_err> error);
            }

            auto& c = child.value();

            // Pass the BPF instructions to the plugin as stdin.
            input << _base_16_encode(_ebpf_inst_to_byte_vector(byte_code)) << std::endl;
            input.pipe().close();
            std::string line;

            // Read the return value from the plugin from stdout.
            while (std::getline(output, line)) {
                return_value_string += line;
            }
            output.close();

            while (std::getline(error, line)) {
                error_string += line;
            }
            c.wait();

            // If the plugin returned a non-zero exit code, then check to see if the error string matches the expected
            // error string.
            if (c.exit_code() != 0) {
                if (return_value_string.empty() && !error_string.empty()) {
                    return_value_string = error_string;
                }
                if (expected_error_string.empty()) {
                    test_results[test] = {
                        bpf_conformance_test_result_t::TEST_RESULT_FAIL,
                        "Plugin returned error code " + std::to_string(c.exit_code()) + " and output " +
                            return_value_string};
                } else {
                    auto cr = return_value_string.find('\r');
                    if (cr != std::string::npos) {
                        return_value_string = return_value_string.substr(0, cr);
                    }
                    if (expected_error_string == return_value_string) {
                        test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_PASS, ""};

                    } else {
                        test_results[test] = {
                            bpf_conformance_test_result_t::TEST_RESULT_FAIL,
                            "Plugin returned error code " + std::to_string(c.exit_code()) + " and output " +
                                return_value_string + " but expected " + expected_error_string};
                    }
                }
                if (debug) {
                    auto [result, message] = test_results[test];
                    std::cerr << "Test:" << test
                              << (result == bpf_conformance_test_result_t::TEST_RESULT_PASS ? "PASS" : "FAIL")
                              << message << std::endl;
                }

                log_debug_result(test_results, test);
                continue;
            }
        } catch (boost::process::process_error& e) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_ERROR,
                "Plugin failed to execute test with error " + std::string(e.what())};
            if (debug) {
                auto [result, message] = test_results[test];
                std::cerr << "Test:" << test
                          << (result == bpf_conformance_test_result_t::TEST_RESULT_PASS ? "PASS" : "FAIL") << message
                          << std::endl;
            }
            log_debug_result(test_results, test);
            continue;
        }

        // Parse the return value from the plugin and compare it with the expected return value.
        uint32_t return_value = 0;
        try {
            return_value = static_cast<uint32_t>(std::stoull(return_value_string, nullptr, 16));
        } catch (const std::exception&) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_ERROR,
                "Plugin returned invalid return value " + return_value_string};
            continue;
        }

        if (return_value != (uint32_t)expected_return_value) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_FAIL,
                "Plugin returned incorrect return value " + return_value_string + " expected " +
                    std::to_string(expected_return_value)};
        } else {
            test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_PASS, ""};
        }
        log_debug_result(test_results, test);
    }

    // If the caller asked for a list of opcodes used by the tests, then print the list.
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
