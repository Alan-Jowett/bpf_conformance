#!/bin/bash
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
#
# Round-trip test for BPF assembler/disassembler using CLI tools.
# Usage: roundtrip_test.sh <bpf_disasm> <bpf_asm> <test_file.data>

set -e

BPF_DISASM="$1"
BPF_ASM="$2"
TEST_FILE="$3"

if [ -z "$BPF_DISASM" ] || [ -z "$BPF_ASM" ] || [ -z "$TEST_FILE" ]; then
    echo "Usage: $0 <bpf_disasm> <bpf_asm> <test_file.data>"
    exit 1
fi

# Step 1: Get original bytecode by disassembling the .data file
ORIGINAL=$("$BPF_DISASM" --file "$TEST_FILE" 2>/dev/null)
if [ -z "$ORIGINAL" ]; then
    echo "SKIP: No bytecode in $TEST_FILE"
    exit 0
fi

# Step 2: Get original hex bytes
ORIGINAL_HEX=$("$BPF_DISASM" --file "$TEST_FILE" --raw 2>/dev/null | sed 's/.*; //' | tr '\n' ' ')

# Step 3: Extract just the assembly (strip line numbers)
ASSEMBLY=$(echo "$ORIGINAL" | sed 's/^[[:space:]]*[0-9]*:[[:space:]]*//')

# Step 4: Re-assemble
REASSEMBLED_HEX=$(echo "$ASSEMBLY" | "$BPF_ASM" --stdin 2>/dev/null)

# Step 5: Disassemble the reassembled output
REASSEMBLED=$("$BPF_DISASM" --program "$REASSEMBLED_HEX" 2>/dev/null)

# Step 6: Compare (strip line numbers for comparison)
ORIGINAL_CLEAN=$(echo "$ORIGINAL" | sed 's/^[[:space:]]*[0-9]*:[[:space:]]*//')
REASSEMBLED_CLEAN=$(echo "$REASSEMBLED" | sed 's/^[[:space:]]*[0-9]*:[[:space:]]*//')

if [ "$ORIGINAL_CLEAN" = "$REASSEMBLED_CLEAN" ]; then
    echo "PASS: $TEST_FILE"
    exit 0
else
    echo "FAIL: $TEST_FILE"
    echo "Original:"
    echo "$ORIGINAL_CLEAN"
    echo "Reassembled:"
    echo "$REASSEMBLED_CLEAN"
    exit 1
fi
