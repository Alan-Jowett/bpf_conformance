// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "ebpf.h"

/**
 * @brief Accept an input stream containing BPF instructions and tuple of ebpf_inst and relocations.
 *
 * @param[in] input Input stream containing BPF instructions to assemble.
 * @return Tuple of Vector of ebpf_inst and relocations.
 */
std::tuple<std::vector<ebpf_inst>, std::map<size_t, std::string>>
bpf_assembler_with_relocations(std::istream& input);
