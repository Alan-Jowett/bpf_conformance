// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Round-trip test for BPF assembler and disassembler.
 *
 * This test validates that the assembler and disassembler are in sync by:
 * 1. Parsing .data test files to extract assembly
 * 2. Assembling to bytecode
 * 3. Disassembling back to assembly
 * 4. Re-assembling the disassembled output
 * 5. Comparing original bytecode with re-assembled bytecode
 *
 * This ensures that as new instructions are added, both components stay synchronized.
 */

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "bpf_assembler.h"
#include "bpf_disassembler.h"
#include "bpf_test_parser.h"

namespace fs = std::filesystem;

// Compare two instruction vectors for equality
static bool
instructions_equal(const std::vector<ebpf_inst>& a, const std::vector<ebpf_inst>& b)
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        if (a[i].opcode != b[i].opcode || a[i].dst != b[i].dst || a[i].src != b[i].src ||
            a[i].offset != b[i].offset || a[i].imm != b[i].imm) {
            return false;
        }
    }
    return true;
}

// Format instruction for debugging output
static std::string
format_inst_hex(const ebpf_inst& inst)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(2) << static_cast<int>(inst.opcode) << " ";
    ss << std::setw(1) << static_cast<int>(inst.dst) << std::setw(1) << static_cast<int>(inst.src) << " ";
    ss << std::setw(4) << static_cast<uint16_t>(inst.offset) << " ";
    ss << std::setw(8) << static_cast<uint32_t>(inst.imm);
    return ss.str();
}

// Test round-trip for a single file
static bool
test_roundtrip(const fs::path& test_file, bool verbose)
{
    try {
        // Step 1: Parse the test file to get original bytecode
        auto [memory, expected_result, error_string, original_bytecode] = parse_test_file(test_file);

        if (original_bytecode.empty()) {
            if (verbose) {
                std::cout << "  SKIP (no bytecode): " << test_file.filename() << std::endl;
            }
            return true; // Not a failure, just skip
        }

        // Step 2: Disassemble the original bytecode
        std::ostringstream disasm_output;
        bpf_disassembler(original_bytecode, disasm_output, false);
        std::string disassembled = disasm_output.str();

        // Step 3: Strip line numbers from disassembly (format: "   N: instruction")
        std::istringstream disasm_stream(disassembled);
        std::ostringstream clean_asm;
        std::string line;
        while (std::getline(disasm_stream, line)) {
            // Find the colon after the line number and extract the instruction
            auto colon_pos = line.find(':');
            if (colon_pos != std::string::npos && colon_pos + 2 < line.length()) {
                clean_asm << line.substr(colon_pos + 2) << "\n";
            }
        }

        // Step 4: Re-assemble the disassembled output
        std::istringstream asm_input(clean_asm.str());
        std::vector<ebpf_inst> reassembled_bytecode;
        try {
            reassembled_bytecode = bpf_assembler(asm_input);
        } catch (const std::exception& e) {
            std::cerr << "  FAIL (reassembly error): " << test_file.filename() << std::endl;
            std::cerr << "    Error: " << e.what() << std::endl;
            std::cerr << "    Disassembled:" << std::endl;
            std::cerr << disassembled << std::endl;
            return false;
        }

        // Step 5: Compare original and reassembled bytecode
        if (!instructions_equal(original_bytecode, reassembled_bytecode)) {
            std::cerr << "  FAIL (mismatch): " << test_file.filename() << std::endl;
            std::cerr << "    Original instructions: " << original_bytecode.size() << std::endl;
            std::cerr << "    Reassembled instructions: " << reassembled_bytecode.size() << std::endl;

            size_t max_len = std::max(original_bytecode.size(), reassembled_bytecode.size());
            for (size_t i = 0; i < max_len; i++) {
                std::cerr << "    [" << i << "] ";
                if (i < original_bytecode.size()) {
                    std::cerr << "orig: " << format_inst_hex(original_bytecode[i]);
                } else {
                    std::cerr << "orig: (none)";
                }
                std::cerr << " | ";
                if (i < reassembled_bytecode.size()) {
                    std::cerr << "re: " << format_inst_hex(reassembled_bytecode[i]);
                } else {
                    std::cerr << "re: (none)";
                }
                if (i < original_bytecode.size() && i < reassembled_bytecode.size()) {
                    if (!instructions_equal({original_bytecode[i]}, {reassembled_bytecode[i]})) {
                        std::cerr << " <-- MISMATCH";
                    }
                }
                std::cerr << std::endl;
            }

            std::cerr << "    Disassembled output:" << std::endl;
            std::cerr << disassembled << std::endl;
            return false;
        }

        if (verbose) {
            std::cout << "  PASS: " << test_file.filename() << std::endl;
        }
        return true;

    } catch (const std::exception& e) {
        std::cerr << "  FAIL (exception): " << test_file.filename() << ": " << e.what() << std::endl;
        return false;
    }
}

int
main(int argc, char* argv[])
{
    bool verbose = false;
    std::string test_directory = "tests";

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        } else if (arg == "--test_directory" && i + 1 < argc) {
            test_directory = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --verbose, -v          Show all test results" << std::endl;
            std::cout << "  --test_directory DIR   Directory containing .data files" << std::endl;
            return 0;
        }
    }

    std::cout << "BPF Assembler/Disassembler Round-Trip Test" << std::endl;
    std::cout << "Test directory: " << test_directory << std::endl;

    int passed = 0;
    int failed = 0;

    // Iterate over all .data files in the test directory
    for (const auto& entry : fs::directory_iterator(test_directory)) {
        if (entry.path().extension() == ".data") {
            if (test_roundtrip(entry.path(), verbose)) {
                passed++;
            } else {
                failed++;
            }
        }
    }

    std::cout << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;

    return failed > 0 ? 1 : 0;
}
