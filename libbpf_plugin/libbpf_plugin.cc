// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This program reads BPF instructions from stdin and memory contents from
// the first agument. It then executes the BPF program and prints the
// value of r0 at the end of execution.
// The program is intended to be used with the bpf conformance test suite.

#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <linux/bpf.h>

// This is a work around for bpf_stats_type enum not being defined in
// linux/bpf.h. This enum is defined in bpf.h in the kernel source tree.
#define bpf_stats_type bpf_stats_type_fake
enum bpf_stats_type_fake {};
#include <bpf/bpf.h>
#undef bpf_stats_type_fake

/**
 * @brief Read in a string of hex bytes and return a vector of bytes.
 *
 * @param[in] input String containing hex bytes.
 * @return Vector of bytes.
 */
std::vector<uint8_t>
base16_decode(const std::string& input)
{
    std::vector<uint8_t> output;
    std::stringstream ss(input);
    std::string value;
    while (std::getline(ss, value, ' ')) {
        try {
            output.push_back(std::stoi(value, nullptr, 16));
        } catch (...) {
            // Ignore invalid values.
        }
    }
    return output;
}

/**
 * @brief Convert a vector of bytes to a vector of bpf_insn.
 *
 * @param[in] bytes Vector of bytes.
 * @return Vector of bpf_insn.
 */
std::vector<bpf_insn>
bytes_to_ebpf_inst(std::vector<uint8_t> bytes)
{
    std::vector<bpf_insn> instructions(bytes.size() / sizeof(bpf_insn));
    memcpy(instructions.data(), bytes.data(), bytes.size());
    return instructions;
}

/**
 * @brief Create a prolog that loads the packet memory into R1 and the lenght into R2.
 *
 * @param[in] size Expected size of the packet.
 * @return Vector of bpf_insn that represents the prolog.
 */
std::vector<bpf_insn>
generate_xdp_prolog(int size)
{
    // Create a prolog that converts the BPF program to one that can be loaded
    // at the XDP attach point.
    // This involves:
    // 1. Copying the ctx->data into r1.
    // 2. Copying the ctx->data_end - ctx->data into r2.
    // 3. Satisfying the verifier that r2 is the length of the packet.
    return {
        {0xb7, 0x0, 0x0, 0x0, -1},   // mov64 r0, -1
        {0xbf, 0x6, 0x1, 0x0, 0x0},  // mov r6, r1
        {0x61, 0x1, 0x6, 0x0, 0x0},  // ldxw r1, [r6+0]
        {0x61, 0x2, 0x6, 0x4, 0x0},  // ldxw r2, [r6+4]
        {0xbf, 0x3, 0x1, 0x0, 0x0},  // mov r3, r1
        {0x7, 0x3, 0x0, 0x0, size},  // add r3, size
        {0xbd, 0x3, 0x2, 0x1, 0x0},  //  jle r3, r2, +1
        {0x95, 0x0, 0x0, 0x0, 0x0},  // exit
        {0xb7, 0x2, 0x0, 0x0, size}, // mov r2, size
    };
}

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first agument. It then executes the BPF program and prints the
 * value of r0 at the end of execution.
 */
int
main(int argc, char** argv)
{
    bool debug = false;
    std::vector<std::string> args(argv, argv + argc);
    if (args.size() > 0) {
        args.erase(args.begin());
    }
    std::string program_string;
    std::string memory_string;

    if (args.size() > 0 && args[0] == "--help") {
        std::cout << "usage: " << argv[0] << " [--program <base16 program bytes>] [<base16 memory bytes>] [--debug]" << std::endl;
        return 1;
    }

    if (args.size() > 1 && args[0] == "--program") {
        args.erase(args.begin());
        program_string = args[0];
        args.erase(args.begin());
    } else {
        std::getline(std::cin, program_string);
    }

    // Next parameter is optional memory contents.
    if (args.size() > 0 && args[0] != "--debug") {
        memory_string = args[0];
        args.erase(args.begin());
    }

    if (args.size() > 0 && args[0] == "--debug") {
        debug = true;
        args.erase(args.begin());
    }

    if (args.size() > 0 && args[0].size() > 0) {
        std::cerr << "Unexpected arguments: " << args[0] << std::endl;
        return 1;
    }

    std::vector<bpf_insn> program = bytes_to_ebpf_inst(base16_decode(program_string));
    std::vector<uint8_t> memory = base16_decode(memory_string);

    // Add prolog if program accesses memory.
    if (memory.size() > 0) {
        auto prolog_instructions = generate_xdp_prolog(memory.size());
        program.insert(program.begin(), prolog_instructions.begin(), prolog_instructions.end());
    }

    // Load program into kernel.
    std::string log;
    log.resize(1024);
    int fd = bpf_load_program(
        BPF_PROG_TYPE_XDP,
        reinterpret_cast<const bpf_insn*>(program.data()),
        static_cast<uint32_t>(program.size()),
        "MIT",
        0,
        &log[0],
        log.size());
    if (fd < 0) {
        if (debug)
            std::cout << "Failed to load program: " << log << std::endl;
        return 1;
    }

    // Run program.
    uint32_t output_value = 0;
    unsigned int out_size = memory.size();
    uint32_t duration;
    int result =
        bpf_prog_test_run(fd, 1, memory.data(), memory.size(), memory.data(), &out_size, &output_value, &duration);
    if (result != 0) {
        if (debug)
            std::cout << "Failed to run program: " << result << std::endl;
        return 1;
    }

    // Print output.
    std::cout << std::hex << output_value << std::endl;

    return 0;
}
