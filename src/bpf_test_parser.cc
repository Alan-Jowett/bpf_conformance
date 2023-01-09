// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_test_parser.h"
#include <filesystem>
#include <fstream>
#include <sstream>

#include "bpf_assembler.h"

std::tuple<
    std::vector<uint8_t>,
    uint64_t,
    std::string,
    std::vector<ebpf_inst>,
    std::map<size_t, std::string>,
    std::vector<std::tuple<std::string, ebpf_map_definition_in_file_t>>>
parse_test_file(const std::filesystem::path& data_file)
{
    enum class _state
    {
        state_ignore,
        state_assembly,
        state_raw,
        state_result,
        state_memory,
        state_error,
        state_map,
    } state = _state::state_ignore;

    std::stringstream data_out;
    std::ifstream data_in(data_file);

    std::string result_string;
    std::string mem;
    std::string line;
    std::string expected_error;
    std::string raw;
    std::vector<std::tuple<std::string, ebpf_map_definition_in_file_t>> maps;

    while (std::getline(data_in, line)) {
        if (line.find("--") != std::string::npos) {
            if (line.find("asm") != std::string::npos) {
                state = _state::state_assembly;
                continue;
            } else if (line.find("result") != std::string::npos) {
                state = _state::state_result;
                continue;
            } else if (line.find("mem") != std::string::npos) {
                state = _state::state_memory;
                continue;
            } else if (line.find("raw") != std::string::npos) {
                state = _state::state_raw;
                continue;
            } else if (line.find("result") != std::string::npos) {
                state = _state::state_result;
                continue;
            } else if (line.find("no register offset") != std::string::npos) {
                state = _state::state_ignore;
                continue;
            } else if (line.find(" c") != std::string::npos) {
                state = _state::state_ignore;
                continue;
            } else if (line.find("error") != std::string::npos) {
                state = _state::state_error;
                continue;
            } else if (line.find("map") != std::string::npos) {
                state = _state::state_map;
                continue;
            } else {
                std::cout << "Skipping: Unknown directive " << line << " in file " << data_file << std::endl;
                return {};
                continue;
            }
        }
        if (line.empty()) {
            continue;
        }

        switch (state) {
        case _state::state_assembly:
            if (line.find("#") != std::string::npos) {
                line = line.substr(0, line.find("#"));
            }
            data_out << line << std::endl;
            break;
        case _state::state_result:
            result_string = line;
            break;
        case _state::state_memory:
            mem += std::string(" ") + line;
            break;
        case _state::state_error:
            expected_error = line;
            break;
        case _state::state_raw:
            raw += std::string(" ") + line;
            break;
        case _state::state_map: {
            std::stringstream ss(line);
            std::string name;
            ss >> name;
            if (name.empty() || (name[0] == '#')) {
                continue;
            }
            ebpf_map_definition_in_file_t map_definition = {};
            ss >> map_definition.type;
            ss >> map_definition.key_size;
            ss >> map_definition.value_size;
            ss >> map_definition.max_entries;
            maps.push_back({name, map_definition});
            break;
        }
        default:
            continue;
        }
    }

    if (expected_error.empty() && result_string.empty()) {
        std::cout << "Skipping: No result or error in test file " << data_file << std::endl;
        return {};
    }

    uint64_t result_value;
    if (result_string.empty()) {
        result_value = 0;
    } else if (result_string.find("0x") != std::string::npos) {
        result_value = std::stoull(result_string, nullptr, 16);
    } else {
        result_value = std::stoull(result_string);
    }

    std::vector<ebpf_inst> instructions;
    std::map<size_t, std::string> relocations;
    if (!raw.empty()) {
        std::stringstream raw_stream(raw);

        std::string byte;
        while (raw_stream >> line) {
            uint64_t value;
            ebpf_inst inst;
            if (line.starts_with("0x")) {
                value = std::stoull(line, nullptr, 16);
            } else {
                value = std::stoull(line);
            }
            *reinterpret_cast<uint64_t*>(&inst) = value;
            instructions.push_back(inst);
        }
    } else {
        data_out.seekg(0);
        auto assembler_output = bpf_assembler_with_relocations(data_out);
        instructions = std::get<0>(assembler_output);
        relocations = std::get<1>(assembler_output);
    }

    if (instructions.empty()) {
        std::cout << "Skipping: No instructions in test file " << data_file << std::endl;
        return {};
    }

    std::vector<uint8_t> input_buffer;

    if (!mem.empty()) {
        std::stringstream ss(mem);
        uint32_t value;
        while (ss >> std::hex >> value) {
            input_buffer.push_back(static_cast<uint8_t>(value));
        }
    }

    return {input_buffer, result_value, expected_error, instructions, relocations, maps};
}
