// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <iostream>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <bpf_conformance_core/ebpf.h>

/**
 * @brief eBPF Map Definition as it appears in the maps section of an ELF file.
 */
typedef struct _ebpf_map_definition_in_file
{
    uint32_t type;          ///< Type of map.
    uint32_t key_size;      ///< Size in bytes of a map key.
    uint32_t value_size;    ///< Size in bytes of a map value.
    uint32_t max_entries;   ///< Maximum number of entries allowed in the map.
    uint32_t inner_map_idx; ///< Index of inner map if this is a nested map.
} ebpf_map_definition_in_file_t;

/**
 * @brief Write a BPF program to an ELF file, using the classic ELF format for maps.
 *
 * @param[out] output Stream to write the ELF file to.
 * @param[in] instructions BPF instructions to write.
 * @param[in] maps BPF maps to write.
 * @param[in] map_relocations Map of map names to their relocations.
 */
void
bpf_writer_classic(
    std::ostream& output,
    const std::string& section_name,
    const std::string& function_name,
    const std::vector<ebpf_inst_t>& instructions,
    const std::vector<std::tuple<std::string, ebpf_map_definition_in_file_t>>& maps,
    const std::map<size_t, std::string>& map_relocations);
