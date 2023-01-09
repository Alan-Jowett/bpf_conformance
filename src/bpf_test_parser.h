// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include "ebpf.h"

/**
 * @brief Parse a test file and return the memory, the expected return value, the expected error string, and the BPF
 * byte code.
 *
 * @param[in] data_file Path to the test file.
 * @return Tuple of input memory, expected return value, the expected error string, the BPF byte code sequence,
 * relocations, and the list of BPF maps.
 */
std::tuple<
    std::vector<uint8_t>,
    uint64_t,
    std::string,
    std::vector<ebpf_inst>,
    std::map<size_t, std::string>,
    std::vector<std::tuple<std::string, ebpf_map_definition_in_file_t>>>
parse_test_file(const std::filesystem::path& data_file);
