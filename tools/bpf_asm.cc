// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Standalone BPF assembler CLI tool.
 *
 * Usage:
 *   bpf_asm --file input.asm
 *   echo "mov %r0, 1\nexit" | bpf_asm --stdin
 *   bpf_asm --help
 */

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <bpf_conformance_core/bpf_assembler.h>

namespace fs = std::filesystem;

static void
print_usage(const char* program_name)
{
    std::cout << "BPF Assembler" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << program_name << " --file <path>" << std::endl;
    std::cout << "  " << program_name << " --stdin" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --file <path>   Assemble from a file" << std::endl;
    std::cout << "  --stdin         Read assembly from stdin" << std::endl;
    std::cout << "  --hex           Output as space-separated hex bytes (default)" << std::endl;
    std::cout << "  --raw           Output raw binary bytes" << std::endl;
    std::cout << "  --help          Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " --file program.asm" << std::endl;
    std::cout << "  echo \"mov %r0, 1\" | " << program_name << " --stdin" << std::endl;
}

static void
output_hex(const std::vector<ebpf_inst>& instructions, std::ostream& out)
{
    for (size_t i = 0; i < instructions.size(); i++) {
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&instructions[i]);
        for (size_t j = 0; j < sizeof(ebpf_inst); j++) {
            if (i > 0 || j > 0) {
                out << " ";
            }
            out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[j]);
        }
    }
    out << std::endl;
}

static void
output_raw(const std::vector<ebpf_inst>& instructions, std::ostream& out)
{
    for (const auto& inst : instructions) {
        out.write(reinterpret_cast<const char*>(&inst), sizeof(ebpf_inst));
    }
}

int
main(int argc, char* argv[])
{
    std::string file_path;
    bool use_stdin = false;
    bool output_raw_bytes = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--file" && i + 1 < argc) {
            file_path = argv[++i];
        } else if (arg == "--stdin") {
            use_stdin = true;
        } else if (arg == "--hex") {
            output_raw_bytes = false;
        } else if (arg == "--raw") {
            output_raw_bytes = true;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    if (file_path.empty() && !use_stdin) {
        std::cerr << "Error: Either --file or --stdin must be specified" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    try {
        std::vector<ebpf_inst> instructions;

        if (use_stdin) {
            // Read from stdin
            std::stringstream buffer;
            buffer << std::cin.rdbuf();
            std::istringstream input(buffer.str());
            instructions = bpf_assembler(input);
        } else {
            // Read from file
            if (!fs::exists(file_path)) {
                std::cerr << "Error: File not found: " << file_path << std::endl;
                return 1;
            }
            std::ifstream file(file_path);
            if (!file) {
                std::cerr << "Error: Cannot open file: " << file_path << std::endl;
                return 1;
            }
            instructions = bpf_assembler(file);
        }

        if (instructions.empty()) {
            std::cerr << "Error: No instructions assembled" << std::endl;
            return 1;
        }

        // Output
        if (output_raw_bytes) {
            output_raw(instructions, std::cout);
        } else {
            output_hex(instructions, std::cout);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
