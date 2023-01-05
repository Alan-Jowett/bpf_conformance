// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "ebpf.h"

/**
 * @brief Accept an input stream containing BPF instructions and return a vector of ebpf_inst.
 *
 * @param[in] input Input stream containing BPF instructions to assemble.
 * @return Vector of ebpf_inst
 */
std::vector<ebpf_inst>
bpf_assembler(std::istream& input);
