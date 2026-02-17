// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Standalone BPF disassembler CLI tool.
 *
 * Usage:
 *   bpf_disasm --program "b4 00 00 00 0a 00 00 00 95 00 00 00 00 00 00 00"
 *   bpf_disasm --file tests/add.data
 *   bpf_disasm --help
 */

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <bpf_conformance_core/bpf_disassembler.h>
#include <bpf_conformance_core/bpf_test_parser.h>

namespace fs = std::filesystem;

// Parse hex string into bytes
static std::vector<uint8_t>
parse_hex_string(const std::string& hex)
{
    std::vector<uint8_t> bytes;
    std::istringstream stream(hex);
    std::string byte_str;

    while (stream >> byte_str) {
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            bytes.push_back(byte);
        } catch (...) {
            // Skip invalid bytes
        }
    }
    return bytes;
}

// Convert bytes to ebpf_inst vector
static std::vector<ebpf_inst>
bytes_to_instructions(const std::vector<uint8_t>& bytes)
{
    std::vector<ebpf_inst> instructions;
    size_t num_instructions = bytes.size() / sizeof(ebpf_inst);

    for (size_t i = 0; i < num_instructions; i++) {
        ebpf_inst inst;
        std::memcpy(&inst, &bytes[i * sizeof(ebpf_inst)], sizeof(ebpf_inst));
        instructions.push_back(inst);
    }
    return instructions;
}

static void
print_usage(const char* program_name)
{
    std::cout << "BPF Disassembler" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << program_name << " --program \"<hex bytes>\"" << std::endl;
    std::cout << "  " << program_name << " --file <path.data>" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --program <hex>   Disassemble hex-encoded BPF bytecode" << std::endl;
    std::cout << "  --file <path>     Disassemble from a .data test file" << std::endl;
    std::cout << "  --raw             Show raw bytes alongside disassembly" << std::endl;
    std::cout << "  --help            Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " --program \"b4 00 00 00 0a 00 00 00 95 00 00 00 00 00 00 00\"" << std::endl;
    std::cout << "  " << program_name << " --file tests/add.data --raw" << std::endl;
}

int
main(int argc, char* argv[])
{
    std::string program_hex;
    std::string file_path;
    bool show_raw = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--program" && i + 1 < argc) {
            program_hex = argv[++i];
        } else if (arg == "--file" && i + 1 < argc) {
            file_path = argv[++i];
        } else if (arg == "--raw") {
            show_raw = true;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    if (program_hex.empty() && file_path.empty()) {
        std::cerr << "Error: Either --program or --file must be specified" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    std::vector<ebpf_inst> instructions;

    try {
        if (!program_hex.empty()) {
            // Parse hex bytes from command line
            auto bytes = parse_hex_string(program_hex);
            if (bytes.size() < sizeof(ebpf_inst)) {
                std::cerr << "Error: Not enough bytes for a valid BPF instruction" << std::endl;
                return 1;
            }
            if (bytes.size() % sizeof(ebpf_inst) != 0) {
                std::cerr << "Warning: Byte count is not a multiple of instruction size (8 bytes)" << std::endl;
            }
            instructions = bytes_to_instructions(bytes);
        } else {
            // Parse from .data file
            if (!fs::exists(file_path)) {
                std::cerr << "Error: File not found: " << file_path << std::endl;
                return 1;
            }
            auto [memory, expected_result, error_string, bytecode] = parse_test_file(file_path);
            instructions = bytecode;

            if (instructions.empty()) {
                std::cerr << "Error: No BPF instructions found in file" << std::endl;
                return 1;
            }
        }

        // Disassemble and output
        bpf_disassembler(instructions, std::cout, show_raw);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
