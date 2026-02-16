// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file provides the Boost.Process-based executor implementation
// and backwards-compatible API wrappers for bpf_conformance.

#include "bpf_conformance.h"
#include "boost_helper.h"
#include "bpf_writer.h"

#include <bpf_conformance_core/bpf_conformance.h>

#include <cstring>
#include <iomanip>
#include <sstream>

namespace {

/**
 * @brief Convert a vector of bytes to a string of hex bytes.
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
 * @brief Convert raw bytecode to ELF format using bpf_writer.
 */
std::vector<uint8_t>
_bytecode_to_elf(
    const std::vector<uint8_t>& bytecode,
    const std::string& section_name,
    const std::string& function_name)
{
    // Convert bytes back to instructions
    std::vector<ebpf_inst> instructions;
    size_t num_inst = bytecode.size() / sizeof(ebpf_inst);
    for (size_t i = 0; i < num_inst; i++) {
        ebpf_inst inst;
        std::memcpy(&inst, &bytecode[i * sizeof(ebpf_inst)], sizeof(ebpf_inst));
        instructions.push_back(inst);
    }

    std::stringstream elf_stream;
    bpf_writer_classic(elf_stream, section_name, function_name, instructions, {}, {});
    std::string elf_string = elf_stream.str();
    return std::vector<uint8_t>(elf_string.begin(), elf_string.end());
}

} // anonymous namespace

/**
 * @brief Create a BPF executor that uses Boost.Process to run an external plugin.
 *
 * @param plugin_path Path to the plugin executable.
 * @param plugin_options Options to pass to the plugin.
 * @param xdp_prolog Whether XDP prolog is being used (affects ELF section name).
 * @return Executor function compatible with bpf_conformance_run().
 */
bpf_executor_fn
make_process_executor(
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    bool xdp_prolog)
{
    return [plugin_path, plugin_options, xdp_prolog](
        const std::vector<uint8_t>& bytecode,
        const std::vector<uint8_t>& memory,
        bool elf_format) -> bpf_execution_result_t
    {
        bpf_execution_result_t result{};

        try {
            boost::process::ipstream output;
            boost::process::ipstream error;
            boost::process::opstream input;

            std::vector<std::string> args;
            if (!memory.empty()) {
                args.push_back(_base_16_encode(memory));
            }
            args.insert(args.end(), plugin_options.begin(), plugin_options.end());
            if (elf_format) {
                args.push_back("--elf");
            }

            boost::process::child c(
                plugin_path.string(),
                boost::process::args(args),
                boost::process::std_out > output,
                boost::process::std_in < input,
                boost::process::std_err > error);

            // Send bytecode to plugin
            if (elf_format) {
                auto elf_bytes = _bytecode_to_elf(
                    bytecode,
                    xdp_prolog ? bpf_conformance_xdp_section_name : bpf_conformance_default_section_name,
                    bpf_conformance_default_function_name);
                input << _base_16_encode(elf_bytes) << std::endl;
            } else {
                input << _base_16_encode(bytecode) << std::endl;
            }
            input.pipe().close();

            // Read output
            std::string line;
            std::string output_str;
            while (std::getline(output, line)) {
                output_str += line + "\n";
            }
            output.close();

            std::string error_str;
            while (std::getline(error, line)) {
                error_str += line + "\n";
            }

            // Strip trailing newlines
            if (!output_str.empty() && output_str.back() == '\n') {
                output_str.pop_back();
            }
            if (!error_str.empty() && error_str.back() == '\n') {
                error_str.pop_back();
            }

            c.wait();

            result.success = true;
            result.exit_code = c.exit_code();
            result.output = output_str;
            result.error_message = error_str;

            // Parse return value if successful
            if (result.exit_code == 0 && !output_str.empty()) {
                try {
                    result.return_value = std::stoull(output_str, nullptr, 16);
                } catch (...) {
                    // Leave return_value as 0
                }
            }

        } catch (boost::process::process_error& e) {
            result.success = false;
            result.exit_code = -1;
            result.error_message = e.what();
        }

        return result;
    };
}

// Backwards-compatible API implementation
std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance_options(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    const bpf_conformance_options_t& options)
{
    auto executor = make_process_executor(plugin_path, plugin_options, options.xdp_prolog);
    return bpf_conformance_run(test_files, executor, options);
}
