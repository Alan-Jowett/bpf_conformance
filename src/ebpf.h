// Copyright (c) Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef EBPF_H
#define EBPF_H

#include "ebpf_inst.h"

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

#endif