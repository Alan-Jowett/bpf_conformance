// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "ebpf.h"

/**
 * @brief Disassemble a vector of ebpf_inst into human-readable assembly.
 *
 * @param[in] instructions Vector of ebpf_inst to disassemble.
 * @param[out] output Output stream for the disassembled text.
 * @param[in] show_raw If true, include raw hex bytes as comments.
 */
void
bpf_disassembler(const std::vector<ebpf_inst>& instructions, std::ostream& output, bool show_raw = false);

/**
 * @brief Disassemble a single instruction to a string.
 *
 * @param[in] inst Instruction to disassemble.
 * @return Human-readable assembly string.
 */
std::string
bpf_disassemble_inst(const ebpf_inst& inst);
