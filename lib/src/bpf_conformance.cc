// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <bpf_conformance_core/bpf_conformance.h>
#include <bpf_conformance_core/bpf_disassembler.h>
#include <bpf_conformance_core/bpf_test_parser.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>

// Internal instruction metadata for tracking used/unused instructions
namespace {

inline bool
needs_src(uint8_t opcode)
{
    return opcode == 0x18 || opcode == 0x85;
}

inline bool
needs_imm(uint8_t opcode)
{
    return opcode == 0xc3 || opcode == 0xd4 || opcode == 0xdb || opcode == 0xdc;
}

inline bool
needs_offset(uint8_t opcode)
{
    return opcode == 0x34 || opcode == 0x37 || opcode == 0x3c || opcode == 0x3f || opcode == 0x94 || opcode == 0x97 ||
           opcode == 0x9c || opcode == 0x9f || opcode == 0xbc || opcode == 0xbf;
}

struct bpf_conformance_instruction_t
{
    bpf_conformance_test_cpu_version_t cpu_version;
    bpf_conformance_groups_t groups;
    uint8_t opcode;
    uint8_t src = 0;
    int32_t imm = 0;
    int16_t offset = 0;

    bpf_conformance_instruction_t(
        bpf_conformance_test_cpu_version_t cpu_version,
        bpf_conformance_groups_t groups,
        uint8_t opcode,
        uint8_t src = 0,
        int32_t imm = 0,
        int16_t offset = 0)
        : cpu_version(cpu_version), groups(groups), opcode(opcode), src(src), imm(imm), offset(offset) {}

    bpf_conformance_instruction_t(
        bpf_conformance_test_cpu_version_t cpu_version, bpf_conformance_groups_t groups, ebpf_inst inst)
        : cpu_version(cpu_version), groups(groups), opcode(inst.opcode)
    {
        src = needs_src(opcode) ? inst.src : 0;
        imm = needs_imm(opcode) ? inst.imm : 0;
        offset = needs_offset(opcode) ? inst.offset : 0;
    }
};

struct InstCmp
{
    bool operator()(const bpf_conformance_instruction_t& a, const bpf_conformance_instruction_t& b) const
    {
        if (a.opcode != b.opcode) return a.opcode < b.opcode;
        if (a.src != b.src) return a.src < b.src;
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.imm < b.imm;
    }
};

// Instructions from the BPF ISA spec (subset for tracking)
const std::set<bpf_conformance_instruction_t, InstCmp> instructions_from_spec = {
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x00},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x04},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x05},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x07},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x0c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x0f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x00},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x95},
    // ... more instructions would go here
};

std::optional<bpf_conformance_instruction_t>
get_instruction_conformance_info(ebpf_inst inst)
{
    auto it = std::find_if(instructions_from_spec.begin(), instructions_from_spec.end(),
        [&](const auto& instruction) {
            return (instruction.opcode == inst.opcode) &&
                   (!needs_src(inst.opcode) || instruction.src == inst.src) &&
                   (!needs_imm(inst.opcode) || instruction.imm == inst.imm) &&
                   (!needs_offset(inst.opcode) || instruction.offset == inst.offset);
        });
    if (it == instructions_from_spec.end()) {
        return {};
    }
    return *it;
}

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

std::vector<uint8_t>
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

void
_log_debug_result(
    const std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>& test_results,
    const std::filesystem::path& test)
{
    auto it = test_results.find(test);
    if (it == test_results.end()) return;
    auto [result, message] = it->second;
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

std::vector<ebpf_inst>
_generate_xdp_prolog(size_t size)
{
    if (size > INT32_MAX) {
        throw std::runtime_error("Packet size too large");
    }
    return {
        {0xb7, 0x0, 0x0, 0x0, -1},
        {0xbf, 0x6, 0x1, 0x0, 0x0},
        {0x61, 0x1, 0x6, 0x0, 0x0},
        {0x61, 0x2, 0x6, 0x4, 0x0},
        {0xbf, 0x3, 0x1, 0x0, 0x0},
        {0x7, 0x3, 0x0, 0x0, static_cast<int>(size)},
        {0xbd, 0x3, 0x2, 0x1, 0x0},
        {0x95, 0x0, 0x0, 0x0, 0x0},
        {0xb7, 0x2, 0x0, 0x0, static_cast<int>(size)},
    };
}

} // anonymous namespace

std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance_run(
    const std::vector<std::filesystem::path>& test_files,
    bpf_executor_fn executor,
    const bpf_conformance_options_t& options)
{
    std::set<bpf_conformance_instruction_t, InstCmp> instructions_used;
    std::set<bpf_conformance_instruction_t, InstCmp> instructions_not_used;
    std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>> test_results;

    for (const auto& test : test_files) {
        // Check include/exclude regex BEFORE parsing
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

        // Parse the test file
        auto [input_memory, expected_return_value, expected_error_string, byte_code] = parse_test_file(test);

        if (byte_code.empty()) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Test file has no BPF instructions."};
            _log_debug_result(test_results, test);
            continue;
        }

        bpf_conformance_test_cpu_version_t required_cpu_version = bpf_conformance_test_cpu_version_t::v1;
        bpf_conformance_groups_t required_conformance_groups{};

        // Determine required CPU version
        for (size_t i = 0; i < byte_code.size(); i++) {
            auto inst = byte_code[i];
            if (auto instruction = get_instruction_conformance_info(inst)) {
                required_cpu_version = std::max(required_cpu_version, instruction->cpu_version);
                required_conformance_groups |= instruction->groups;
            }
            if (inst.opcode == EBPF_OP_LDDW) {
                i++;
            }
        }

        // Skip if unsupported
        if (required_cpu_version > options.cpu_version ||
            (required_conformance_groups & ~options.groups) != bpf_conformance_groups_t::none) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_SKIP, "Test file contains unsupported instructions."};
            _log_debug_result(test_results, test);
            continue;
        }

        for (const auto& inst : byte_code) {
            instructions_used.insert(
                bpf_conformance_instruction_t(required_cpu_version, required_conformance_groups, inst));
        }

        // Add XDP prolog if needed
        if (options.xdp_prolog && !input_memory.empty()) {
            auto prolog = _generate_xdp_prolog(input_memory.size());
            byte_code.insert(byte_code.begin(), prolog.begin(), prolog.end());
        }

        // Debug output
        if (options.debug) {
            std::cerr << "Test file: " << test << std::endl;
            std::cerr << "Input memory: " << _base_16_encode(input_memory) << std::endl;
            std::cerr << "Expected return value: " << expected_return_value << std::endl;
            std::cerr << "Expected error string: " << expected_error_string << std::endl;
            std::cerr << "Byte code: " << _base_16_encode(_ebpf_inst_to_byte_vector(byte_code)) << std::endl;
            std::cerr << "Disassembly:" << std::endl;
            bpf_disassembler(byte_code, std::cerr, false);
        }

        // Convert instructions to bytecode
        std::vector<uint8_t> bytecode = _ebpf_inst_to_byte_vector(byte_code);

        // Execute via the provided executor
        bpf_execution_result_t exec_result;
        try {
            exec_result = executor(bytecode, input_memory, options.elf_format);
        } catch (const std::exception& e) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_ERROR,
                "Executor failed with error: " + std::string(e.what())};
            _log_debug_result(test_results, test);
            continue;
        }

        // Process execution result
        if (!exec_result.success || exec_result.exit_code != 0) {
            std::string return_value_string = exec_result.output;
            if (return_value_string.empty() && !exec_result.error_message.empty()) {
                return_value_string = exec_result.error_message;
            }

            if (expected_error_string.empty()) {
                test_results[test] = {
                    bpf_conformance_test_result_t::TEST_RESULT_ERROR,
                    "Executor returned error code " + std::to_string(exec_result.exit_code) +
                        " and output " + return_value_string};
            } else {
                // Strip trailing whitespace
                auto cr = return_value_string.find('\r');
                if (cr != std::string::npos) {
                    return_value_string = return_value_string.substr(0, cr);
                }
                return_value_string = std::regex_replace(return_value_string, std::regex("\\s+$"), "");

                if (expected_error_string == return_value_string) {
                    test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_PASS, ""};
                } else {
                    test_results[test] = {
                        bpf_conformance_test_result_t::TEST_RESULT_FAIL,
                        "Executor returned error code " + std::to_string(exec_result.exit_code) +
                            " and output " + return_value_string + " but expected " + expected_error_string};
                }
            }

            if (options.debug) {
                auto [result, message] = test_results[test];
                std::cerr << "Test: \"" << test << "\" "
                          << (result == bpf_conformance_test_result_t::TEST_RESULT_PASS ? "PASS" : "FAIL");
                if (!message.empty()) std::cerr << "\n" << message;
                std::cerr << std::endl;
            }
            _log_debug_result(test_results, test);
            continue;
        }

        // Parse return value
        uint64_t return_value = 0;
        try {
            return_value = exec_result.return_value;
        } catch (const std::exception&) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_ERROR,
                "Executor return value could not be parsed (" + exec_result.output + ")"};
            continue;
        }

        if (return_value != expected_return_value) {
            test_results[test] = {
                bpf_conformance_test_result_t::TEST_RESULT_FAIL,
                "Executor returned incorrect return value " + std::to_string(return_value) +
                    " expected " + std::to_string(expected_return_value)};
        } else {
            test_results[test] = {bpf_conformance_test_result_t::TEST_RESULT_PASS, ""};
        }
        _log_debug_result(test_results, test);
    }

    // Compute unused instructions
    for (const auto& instruction : instructions_from_spec) {
        if (instructions_used.find(instruction) == instructions_used.end()) {
            instructions_not_used.insert(instruction);
        }
    }

    // Print instruction lists if requested
    if (options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_USED ||
        options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_ALL) {
        std::cout << "Instructions used by tests:" << std::endl;
        for (const auto& instruction : instructions_used) {
            std::cout << "0x" << std::hex << (uint32_t)instruction.opcode << std::dec << std::endl;
        }
    }

    if (options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_UNUSED ||
        options.list_instructions_option == bpf_conformance_list_instructions_t::LIST_INSTRUCTIONS_ALL) {
        std::cout << "Instructions not used by tests:" << std::endl;
        for (const auto& instruction : instructions_not_used) {
            std::cout << "0x" << std::hex << (uint32_t)instruction.opcode << std::dec << std::endl;
        }
    }

    return test_results;
}
