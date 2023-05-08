// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This program reads BPF instructions from stdin and memory contents from
// the first argument. It then executes the BPF program and prints the
// value of %r0 at the end of execution.
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
#include <bpf/libbpf.h>
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

// Decode BPF instructions from program string and load them into the kernel.
int load_bpf_instructions(const std::string& program_string, size_t memory_length, std::string& log) {
    std::vector<bpf_insn> program = bytes_to_ebpf_inst(base16_decode(program_string));

    // Load program into kernel.
    constexpr uint32_t log_size = 1024;
    log.resize(log_size);
#ifdef USE_DEPRECATED_LOAD_PROGRAM
    int fd = bpf_load_program(
        BPF_PROG_TYPE_XDP,
        reinterpret_cast<const bpf_insn*>(program.data()),
        static_cast<uint32_t>(program.size()),
        "MIT",
        0,
        &log[0],
        log_size);
#else
    bpf_prog_load_opts opts{
        .sz = sizeof(opts),
        .attempts = 1,
        .expected_attach_type = BPF_XDP,
        .log_size = log_size,
        .log_buf = &log[0],
    };
    int fd = bpf_prog_load(
        BPF_PROG_TYPE_XDP,
        "conformance_test",
        "MIT",
        reinterpret_cast<const bpf_insn*>(program.data()),
        program.size(),
        &opts);
#endif
    return fd;
}

int load_elf_file(const std::string& file_contents, std::string& log)
{
    std::vector<uint8_t> bytes = base16_decode(file_contents);
    struct bpf_object* object = nullptr;
    struct bpf_program* program = nullptr;
    struct bpf_map* map = nullptr;
    int fd = -1;
    int error = 0;
    bool result = false;
    bpf_object_open_opts opts = {};
    opts.sz = sizeof(opts);
    opts.relaxed_maps = true;

    // Load ELF file from memory
    object = bpf_object__open_mem(bytes.data(), bytes.size(), &opts);
    if (!object) {
        log = "Failed to load ELF file";
        return -1;
    }

    if (bpf_object__load(object) < 0) {
        log = "Failed to load ELF file";
        return -1;
    }

    // Find the first XDP program.
    bpf_object__for_each_program(program, object) {
        if (bpf_program__get_type(program) == BPF_PROG_TYPE_XDP) {
            fd = bpf_program__fd(program);
            break;
        }
    }

    return fd;
}

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first argument. It then executes the BPF program and prints the
 * value of %r0 at the end of execution.
 */
int
main(int argc, char** argv)
{
    bool debug = false;
    bool elf = false;
    std::vector<std::string> args(argv, argv + argc);
    if (args.size() > 0) {
        args.erase(args.begin());
    }
    std::string program_string;
    std::string memory_string;

    if (args.size() > 0 && args[0] == "--help") {
        std::cout << "usage: " << argv[0] << " [--program <base16 program bytes>] [<base16 memory bytes>] [--debug] [--elf]" << std::endl;
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
    if (args.size() > 0 && !args[0].starts_with("--")) {
        memory_string = args[0];
        args.erase(args.begin());
    }

    if (args.size() > 0 && args[0] == "--debug") {
        debug = true;
        args.erase(args.begin());
    }

    if (args.size() > 0 && args[0] == "--elf") {
        elf = true;
        args.erase(args.begin());
    }

    if (args.size() > 0 && args[0].size() > 0) {
        std::cerr << "Unexpected arguments: " << args[0] << std::endl;
        return 1;
    }

    std::vector<uint8_t> memory = base16_decode(memory_string);
    std::string log;
    int fd = -1;
    if (!elf) {
        fd = load_bpf_instructions(program_string, memory.size(), log);
    }
    else {
        fd = load_elf_file(program_string, log);
    }

    if (fd < 0) {
        if (debug)
            std::cout << "Failed to load program: " << log << std::endl;
        return 1;
    }

    // Run program.
    bpf_test_run_opts test_run{
        .sz = sizeof(bpf_test_run_opts),
        .data_in = memory.data(),
        .data_out = memory.data(),
        .data_size_in = static_cast<uint32_t>(memory.size()),
        .data_size_out = static_cast<uint32_t>(memory.size()),
        .repeat = 1,
    };
    int result = bpf_prog_test_run_opts(fd, &test_run);
    if (result == 0) {
        // Print output.
        std::cout << std::hex << test_run.retval << std::endl;
    }

    return 0;
}
