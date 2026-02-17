// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Boost.Process executor implementation for bpf_conformance.
// This file provides the backwards-compatible bpf_conformance_options() API
// by creating a Boost.Process-based executor and calling bpf_conformance_run().

#include "bpf_conformance.h"
#include "boost_helper.h"

#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Create a Boost.Process-based executor.
 *
 * @param plugin_path Path to the plugin executable.
 * @param plugin_options Options to pass to the plugin.
 * @return Executor function for bpf_conformance_run().
 */
static bpf_conformance_executor_t
make_boost_process_executor(
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options)
{
    return [plugin_path, plugin_options](
        const std::string& input_data,
        const std::vector<std::string>& args) -> bpf_conformance_plugin_result_t
    {
        bpf_conformance_plugin_result_t result{};

        boost::process::ipstream output;
        boost::process::ipstream error;
        boost::process::opstream input;

        // Merge args with plugin_options, maintaining original order:
        // [input_memory, plugin_options..., --elf (if present)]
        // args comes in as [input_memory, --elf (optional)]
        // We need to insert plugin_options in the middle
        std::vector<std::string> all_args;
        
        // Add input_memory if present (first element of args if args not empty and not --elf)
        auto args_iter = args.begin();
        if (args_iter != args.end() && *args_iter != "--elf") {
            all_args.push_back(*args_iter);
            ++args_iter;
        }
        
        // Add plugin_options
        all_args.insert(all_args.end(), plugin_options.begin(), plugin_options.end());
        
        // Add remaining args (like --elf)
        all_args.insert(all_args.end(), args_iter, args.end());

        boost::process::child c(
            plugin_path.string(),
            boost::process::args(all_args),
            boost::process::std_out > output,
            boost::process::std_in < input,
            boost::process::std_err > error);

        // Send input data to plugin stdin
        input << input_data << std::endl;
        input.pipe().close();

        // Read stdout and stderr concurrently to avoid deadlock
        // if plugin writes enough to fill the stderr pipe while we're blocked reading stdout.
        std::string stdout_content;
        std::string stderr_content;

        std::thread stdout_reader([&output, &stdout_content]() {
            std::string line;
            while (std::getline(output, line)) {
                stdout_content += line + "\n";
            }
        });

        std::thread stderr_reader([&error, &stderr_content]() {
            std::string line;
            while (std::getline(error, line)) {
                stderr_content += line + "\n";
            }
        });

        stdout_reader.join();
        stderr_reader.join();

        result.stdout_output = std::move(stdout_content);
        result.stderr_output = std::move(stderr_content);

        c.wait();
        result.exit_code = c.exit_code();

        return result;
    };
}

std::map<std::filesystem::path, std::tuple<bpf_conformance_test_result_t, std::string>>
bpf_conformance_options(
    const std::vector<std::filesystem::path>& test_files,
    const std::filesystem::path& plugin_path,
    const std::vector<std::string>& plugin_options,
    const bpf_conformance_options_t& options)
{
    auto executor = make_boost_process_executor(plugin_path, plugin_options);
    return bpf_conformance_run(test_files, executor, options);
}
