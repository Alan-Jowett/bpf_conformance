// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This program reads BPF instructions from stdin and memory contents from
// the first argument. It then executes the BPF program and prints the
// value of %r0 at the end of execution.
// The program is intended to be used with the bpf conformance test suite.

#include <bpf/libbpf_legacy.h>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <linux/bpf_common.h>
#include <memory>
#include <sys/types.h>
#include <tuple>
#include <vector>
#include <string>
#include <sstream>
#include <linux/bpf.h>

// This is a work around for bpf_stats_type enum not being defined in
// linux/bpf.h. This enum is defined in bpf.h in the kernel source tree.
#define bpf_stats_type bpf_stats_type_fake
enum bpf_stats_type_fake
{
};
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#undef bpf_stats_type_fake

#include "../include/bpf_conformance.h"

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

std::vector<bpf_insn>
generate_64_bit_return_value_fixup(uint32_t map_fd)
{
    std::vector<bpf_insn> result(5);

    result[0] = {};
    result[0].code = BPF_CALL | BPF_JMP;
    result[0].src_reg = 1;
    result[0].imm = 4;
    result[0].dst_reg = 0;

    // Load a pointer to the map into r1.
    result[1].code = BPF_IMM | BPF_DW | BPF_LD;
    result[1].off = 0;
    result[1].src_reg = 2;
    result[1].dst_reg = 1;
    result[1].imm = map_fd;

    // next_imm = 0.
    result[2] = {};

    // move r0 to the map.
    result[3] = {};
    result[3].code = BPF_MEM | BPF_DW | BPF_STX;
    result[3].dst_reg = 1;
    result[3].src_reg = 0;

    // exit.
    result[4] = {};
    result[4].code = BPF_EXIT | BPF_JMP;

    return result;
}

// Decode BPF instructions from program string and load them into the kernel.
int
load_bpf_instructions(const std::string& program_string, int map_fd, size_t memory_length, std::string& log)
{
    auto main = bytes_to_ebpf_inst(base16_decode(program_string));
    auto return_value_fixup = generate_64_bit_return_value_fixup(map_fd);
    decltype(return_value_fixup) program{};

    program.insert(program.end(), return_value_fixup.begin(), return_value_fixup.end());
    program.insert(program.end(), main.begin(), main.end());

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

static int
bpf_elf_file_prepare_load_handler(struct bpf_program* prog, struct bpf_prog_load_opts* _unused, long map_fd)
{
    auto orig_bpf_insns_cnt = bpf_program__insn_cnt(prog);
    auto orig_bpf_insns_data = bpf_program__insns(prog);
    auto orig_bpf_insns_data_size = sizeof(struct bpf_insn) * orig_bpf_insns_cnt;

    auto return_value_prolog_insns = generate_64_bit_return_value_fixup(map_fd);
    auto return_value_prolog_insns_cnt = return_value_prolog_insns.size();
    auto return_value_prolog_insns_data = return_value_prolog_insns.data();
    auto return_value_prolog_insns_data_size = return_value_prolog_insns.size() * sizeof(struct bpf_insn);

    auto new_insns = std::make_unique<struct bpf_insn[]>(return_value_prolog_insns_cnt + orig_bpf_insns_cnt);
    std::memcpy(new_insns.get(), return_value_prolog_insns_data, return_value_prolog_insns_data_size);
    std::memcpy(new_insns.get() + return_value_prolog_insns_cnt, orig_bpf_insns_data, orig_bpf_insns_data_size);

    if (bpf_program__set_insns(prog, new_insns.get(), return_value_prolog_insns_cnt + orig_bpf_insns_cnt) < 0) {
        return -1;
    }
    return 1;
}

std::tuple<int, struct bpf_object*>
load_elf_file(const std::string& file_contents, int map_fd, std::string& log)
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

    libbpf_prog_handler_opts handler_opts = {};
    handler_opts.sz = sizeof(libbpf_prog_handler_opts);
    handler_opts.cookie = map_fd;
    handler_opts.prog_prepare_load_fn = bpf_elf_file_prepare_load_handler;

    int default_program_handler_handler = 0;
    int xdp_program_handler_handle = 0;

    // No matter whether this elf file was encoded with an xdp prolog or not, we will need to intercept its loading
    // and add the appropriate prolog to handle 64-bit return values.
    if ((xdp_program_handler_handle = libbpf_register_prog_handler(
             bpf_conformance_xdp_section_name.c_str(), BPF_PROG_TYPE_XDP, BPF_XDP, &handler_opts)) < 0) {
        log = "Failed to load ELF file: Could not register load handler.";
        return {-1, nullptr};
    }
    if ((default_program_handler_handler = libbpf_register_prog_handler(
             bpf_conformance_default_section_name.c_str(), BPF_PROG_TYPE_XDP, BPF_XDP, &handler_opts)) < 0) {
        log = "Failed to load ELF file: Could not register load handler.";
        return {-1, nullptr};
    }

    // Load ELF file from memory
    object = bpf_object__open_mem(bytes.data(), bytes.size(), &opts);
    if (!object) {
        log = "Failed to load ELF file: bpf_object__open_mem failed.";
        return {-1, nullptr};
    }

    if (bpf_object__load(object) < 0) {
        log = "Failed to load ELF file";
        return {-1, nullptr};
    }

    // Find the first XDP program.
    bpf_object__for_each_program(program, object)
    {
        if (bpf_program__get_type(program) == BPF_PROG_TYPE_XDP) {
            fd = bpf_program__fd(program);
            break;
        }
    }

    // Unregister the handlers that we registered above.
    if (libbpf_unregister_prog_handler(default_program_handler_handler) < 0) {
        log = "Failed to load ELF file: Could not unload the registered program handler for default programs.";
        return {-1, nullptr};
    }
    if (libbpf_unregister_prog_handler(xdp_program_handler_handle) < 0) {
        log = "Failed to load ELF file: Could not unload the registered program handler for xdp programs.";
        return {-1, nullptr};
    }
    return {fd, object};
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

    union bpf_attr create_map_attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(uint64_t),
        .max_entries = 1,
    };
    auto map = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(int), sizeof(uint64_t), 1, NULL);

    std::vector<uint8_t> memory = base16_decode(memory_string);
    std::string log;
    int fd = -1;
    struct bpf_object* elf_object = nullptr;
    if (!elf) {
        fd = load_bpf_instructions(program_string, map, memory.size(), log);
    } else {
        std::tie(fd, elf_object) = load_elf_file(program_string, map, log);
    }

    if (fd < 0) {
        if (debug)
            std::cout << "Failed to load program: " << log << std::endl;
        return 1;
    }
    if (elf && !elf_object) {
        if (debug) {
            std::cout << "Failed to load problem: The ELF file containing the BPF program "
                         "could not be converted to a BPF object."
                      << std::endl;
            std::cout << "For debugging: " << log << std::endl;
        }
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
        uint64_t r0_result{};
        uint64_t r0_key{0};
        if (bpf_map_lookup_elem(map, &r0_key, &r0_result) == 0) {
            // Print output.
            std::cout << std::hex << r0_result << std::endl;
        }
    }

    if (elf) {
        assert(elf_object != nullptr);
        bpf_object__close(elf_object);
    }

    return 0;
}
