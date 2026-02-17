// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <filesystem>
#include <string>
#include <tuple>
#include <vector>
#include "ebpf.h"

/**
 * @brief Parse a test file and return the memory, the expected return value, the expected error string, and the BPF
 * byte code.
 *
 * @param[in] data_file Path to the test file.
 * @return Tuple of input memory, expected return value, the expected error string, and the BPF byte code sequence.
 */
std::tuple<std::vector<uint8_t>, uint64_t, std::string, std::vector<ebpf_inst>>
parse_test_file(const std::filesystem::path& data_file);
