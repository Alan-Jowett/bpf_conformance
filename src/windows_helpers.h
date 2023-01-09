// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <map>
#include <string>

// This file was generated from bpf_helper_defs.h in the eBPF for Windows headers.

inline std::map<std::string, uint32_t> windows_helper_functions = {
    {"bpf_map_lookup_elem ", 1},
    {"bpf_map_update_elem ", 2},
    {"bpf_map_delete_elem ", 3},
    {"bpf_map_lookup_and_delete_elem ", 4},
    {"bpf_tail_call ", 5},
    {"bpf_get_prandom_u32 ", 6},
    {"bpf_ktime_get_boot_ns ", 7},
    {"bpf_get_smp_processor_id ", 8},
    {"bpf_ktime_get_ns ", 9},
    {"bpf_csum_diff ", 10},
    {"bpf_ringbuf_output ", 11},
    {"bpf_trace_printk2 ", 12},
    {"bpf_trace_printk3 ", 13},
    {"bpf_trace_printk4 ", 14},
    {"bpf_trace_printk5 ", 15},
    {"bpf_map_push_elem ", 16},
    {"bpf_map_pop_elem ", 17},
    {"bpf_map_peek_elem ", 18},
    {"bpf_get_current_pid_tgid ", 19},
};