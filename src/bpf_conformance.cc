// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "../include/bpf_conformance.h"

#include <boost/process.hpp>
#include <fstream>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "bpf_test_parser.h"
#include "bpf_writer.h"
#include "opcode_names.h"
#include "linux_helpers.h"
#include "windows_helpers.h"

const std::string xdp_section_name = "xdp";
const std::string default_section_name = ".text";
const std::string default_function_name = "main";

/**
 * @brief Convert a vector of bytes to a string of hex bytes.
 *
 * @param[in] data Vector of bytes to convert.
 * @return String of hex bytes.
 */
static std::string
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
static std::vector<uint8_t>
_ebpf_inst_to_byte_vector(const std::vector<ebpf_inst>& instructions)
{
    std::vector<uint8_t> result;
    for (auto instruction : instructions) {
        uint8_t* instruction_bytes = reinterpret_cast<uint8_t*>(&instruction);
        for (size_t i = 0; i < sizeof(ebpf_inst); i++) {
            result.push_back(instruction_bytes[i]);
        }
    }
    return result;
}

/**
 * @brief Convert a vector of ebpf instructions, map definitions, and relocation information to an ELF file.
 *
 * @param[in] instructions Instructions to convert.
 * @return Vector of bytes that represents the ELF file.
 */
static std::vector<uint8_t>
_ebpf_inst_to_elf_file(
    const std::string& section_name,
    const std::string& function_name,
    const std::vector<ebpf_inst>& instructions,
    const std::vector<std::tuple<std::string, ebpf_map_definition_in_file_t>>& maps,
    const std::map<size_t, std::string>& map_relocations)
{
    std::stringstream elf_file;
    bpf_writer_classic(elf_file, section_name, function_name, instructions, maps, map_relocations);
    std::string elf_file_string = elf_file.str();
    std::vector<uint8_t> result(elf_file_string.size());
    std::copy(elf_file_string.begin(), elf_file_string.end(), result.begin());
    return result;
}

static void
_log_debug_result(
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
    case bpf_conformance_test_result_t::TEST_RESULT_UNKNOWN:
        std::cout << "Test " << test << " result unknown: " << message << std::endl;
        break;
    }
}

/**
 * @brief Create a prolog that loads the packet memory into R1 and the length into R2.
 *
 * @param[in] size Expected size of the packet.
 * @return Vector of bpf_insn that represents the prolog.
 */
static std::vector<ebpf_inst>
_generate_xdp_prolog(size_t size)
{
    int32_t size32 = static_cast<int32_t>(size);
    // Create a prolog that converts the BPF program to one that can be loaded
    // at the XDP attach point.
    // This involves:
    // 1. Copying the ctx->data into r1.
    // 2. Copying the ctx->data_end - ctx->data into r2.
    // 3. Satisfying the verifier that r2 is the length of the packet.
    return {
        {0xb7, 0x0, 0x0, 0x0, -1},     // mov64 r0, -1
        {0xbf, 0x6, 0x1, 0x0, 0x0},    // mov r6, r1
        {0x61, 0x1, 0x6, 0x0, 0x0},    // ldxw r1, [r6+0]
        {0x61, 0x2, 0x6, 0x4, 0x0},    // ldxw r2, [r6+4]
        {0xbf, 0x3, 0x1, 0x0, 0x0},    // mov r3, r1
        {0x7, 0x3, 0x0, 0x0, size32},  // add r3, size
        {0xbd, 0x3, 0x2, 0x1, 0x0},    //  jle r3, r2, +1
        {0x95, 0x0, 0x0, 0x0, 0x0},    // exit
        {0xb7, 0x2, 0x0, 0x0, size32}, // mov r2, size
    };
}

std::map<std::string, std::map<std::string, uint32_t>> _platform_helper_function_mappings = {
    {"linux", linux_helper_functions}, {"windows", windows_helper_functions}};

std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance_options(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    const bpf_conformance_options_t& options)
{
    std::set<bpf_conformance_instruction_t, InstCmp> instructions_used;
    std::set<bpf_conformance_instruction_t, InstCmp> instructions_not_used;
    std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>> test_results;

    for (auto& test : test_files) {
        // Parse the test file and extract:
        // Input memory contents - Memory to pass to the BPF program.
        // Expected return value - Expected return value from the BPF program.
        // Expected error string - String returned by BPF runtime if the program fails.
        // BPF instructions - Instructions to pass to the BPF program.
        // Relocations - Relocations to pass to the BPF program.
        // Maps - Maps to pass to the BPF program.
        auto [input_memory, expected_return_value, expected_error_string, byte_code, relocations, maps] =
            parse_test_file(test);

        if (!options.elf_format && (maps.size() > 0 || relocations.size() > 0)) {
            test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Test requires ELF format."};
            continue;
        }

        std::map<size_t, std::string> map_relocations;
        bool relocation_error = false;

        // Perform relocations on call instructions and replace with platform specific helper functions ids.
        if (relocations.size() > 0) {
            for (auto& relocation : relocations) {
                if (byte_code[relocation.first].opcode == EBPF_OP_CALL) {
                    auto mapping = _platform_helper_function_mappings.find(options.platform);
                    if ((mapping == _platform_helper_function_mappings.end()) ||
                        (mapping->second.find(relocation.second) == mapping->second.end())) {
                        test_results[test] = {
                            bpf_conformance_test_result_t::TEST_RESULT_SKIP,
                            std::string("Test requires helper function ") + relocation.second +
                                std::string(" that is not supported on this platform.")};
                        relocation_error = true;
                        break;
                    }

                    byte_code[relocation.first].imm = mapping->second[relocation.second];
                } else {
                    map_relocations[relocation.first] = relocation.second;
                }
            }
        }

        if (relocation_error) {
            continue;
        }

        if (options.include_test_regex.has_value()) {
            std::regex include_regex(options.include_test_regex.value_or(""));
            if (!std::regex_search(test.filename().string(), include_regex)) {
                test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Skipped by include regex."};
                continue;
            }
        }

        if (options.exclude_test_regex.has_value()) {
            std::regex exclude_regex(options.exclude_test_regex.value_or(""));
            if (std::regex_search(test.filename().string(), exclude_regex)) {
                test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Skipped by exclude regex."};
                continue;
            }
        }

        // It the test file has no BPF instructions, then skip it.
        if (byte_code.size() == 0) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Test file has no BPF instructions."};
            _log_debug_result(test_results, test);
            continue;
        }

        bpf_conformance_test_cpu_version_t required_cpu_version = bpf_conformance_test_cpu_version_t::v1;

        // Determine the required CPU version for the test.
        for (size_t i = 0; i < byte_code.size(); i++) {
            auto inst = byte_code[i];
            // If this is an atomic store, then the test requires CPU version 3.
            if (((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_STX) &&
                (((inst.opcode & EBPF_MODE_ATOMIC) == EBPF_MODE_ATOMIC))) {
                required_cpu_version = std::max(required_cpu_version, bpf_conformance_test_cpu_version_t::v3);
            }
            // If this is a EBPF_CLS_JMP32, then we know this is v3.
            else if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP32) {
                required_cpu_version = std::max(required_cpu_version, bpf_conformance_test_cpu_version_t::v3);
            } else if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP) {
                // If this is a EBPF_CLS_JMP, then check if it is a less than operation.
                if ((inst.opcode & EBPF_ALU_OP_MASK) >= (EBPF_OP_JLT_IMM & EBPF_ALU_OP_MASK)) {
                    // It his is a less than operation, then we know this is v2.
                    required_cpu_version = std::max(required_cpu_version, bpf_conformance_test_cpu_version_t::v2);
                }
            }
            // If the program uses local or runtime calls then this is v3 of the ABI.
            // inst.src == 0 means helper function call.
            // inst.src == 1 means local function call.
            // inst.src == 2 means runtime function call.
            if (inst.opcode == EBPF_OP_CALL && inst.src != 0) {
                required_cpu_version = std::max(required_cpu_version, bpf_conformance_test_cpu_version_t::v3);
            }
            if (inst.opcode == EBPF_OP_LDDW) {
                // Instruction has a 64-bit immediate and takes two instructions slots.
                i++;
            }
        }

        // If the test requires a CPU version that is not supported by the current CPU version, then skip the test.
        if (required_cpu_version > options.cpu_version) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Test file contains unsupported instructions."};
            _log_debug_result(test_results, test);
            continue;
        }

        for (const auto& inst : byte_code) {
            instructions_used.insert(bpf_conformance_instruction_t(inst));
        }

        // If the caller requires this as a XDP program, then add the prolog instructions.
        if (options.xdp_prolog && input_memory.size() > 0) {
            auto prolog_instructions = _generate_xdp_prolog(input_memory.size());
            byte_code.insert(byte_code.begin(), prolog_instructions.begin(), prolog_instructions.end());
        }

        // If caller requested debug output, then print the test file name, input memory, and BPF instructions.
        if (options.debug) {
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
            std::vector<std::string> args;
            // Construct the command line arguments to pass to the plugin.
            // First argument is any memory to pass to the BPF program.
            // Remaining arguments are the options to pass to the plugin.
            if (input_memory.size() > 0) {
                args.insert(args.begin(), _base_16_encode(input_memory));
            }
            args.insert(args.end(), plugin_options.begin(), plugin_options.end());

            if (options.elf_format) {
                args.insert(args.end(), "--elf");
            }

            boost::process::child c(
                plugin_path.string(),
                boost::process::args(args),
                boost::process::std_out > output,
                boost::process::std_in<input, boost::process::std_err> error);

            // Pass the BPF instructions to the plugin as stdin.
            if (options.elf_format) {
                // Encode the instructions as an ELF file.
                auto elf_file = _ebpf_inst_to_elf_file(
                    options.xdp_prolog ? xdp_section_name : default_section_name,
                    default_function_name,
                    byte_code,
                    maps,
                    map_relocations);
                if (options.save_elf_files) {

                    std::filesystem::path elf_file_path =
                        std::filesystem::temp_directory_path() / test.filename().replace_extension(".o");
                    std::ofstream elf_file_stream(elf_file_path, std::ios::binary);
                    elf_file_stream.write(reinterpret_cast<const char*>(elf_file.data()), elf_file.size());
                    elf_file_stream.close();
                }
                input << _base_16_encode(elf_file) << std::endl;
            } else {
                // Encode the instructions as a byte array.
                input << _base_16_encode(_ebpf_inst_to_byte_vector(byte_code)) << std::endl;
            }
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
                if (options.debug) {
                    auto [result, message] = test_results[test];
                    std::cerr << "Test:" << test
                              << (result == bpf_conformance_test_result_t::TEST_RESULT_PASS ? "PASS" : "FAIL")
                              << message << std::endl;
                }

                _log_debug_result(test_results, test);
                continue;
            }
        } catch (boost::process::process_error& e) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_ERROR,
                "Plugin failed to execute test with error " + std::string(e.what())};
            if (options.debug) {
                auto [result, message] = test_results[test];
                std::cerr << "Test:" << test
                          << (result == bpf_conformance_test_result_t::TEST_RESULT_PASS ? "PASS" : "FAIL") << message
                          << std::endl;
            }
            _log_debug_result(test_results, test);
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
        _log_debug_result(test_results, test);
    }

    // Compute list of opcodes not used in tests.
    for (auto& instruction : instructions_from_spec) {
        if (instructions_used.find(instruction) == instructions_used.end()) {
            instructions_not_used.insert(instruction);
        }
    }

    // If the caller asked for a list of opcodes used by the tests, then print the list.

    if (options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_USED ||
        options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_ALL) {
        std::cout << "Instructions used by tests:" << std::endl;
        for (auto instruction : instructions_used) {
            std::cout << instruction_to_name(instruction) << std::endl;
        }
    }

    if (options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_UNUSED ||
        options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_ALL) {
        std::cout << "Instructions not used by tests:" << std::endl;
        for (auto instruction : instructions_not_used) {
            std::cout << instruction_to_name(instruction) << std::endl;
        }
    }

    return test_results;
}
