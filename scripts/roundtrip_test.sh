#!/bin/bash
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
#
# Round-trip test for BPF assembler/disassembler using CLI tools.
# Usage: roundtrip_test.sh <bpf_disasm> <bpf_asm> <test_directory>

BPF_DISASM="$1"
BPF_ASM="$2"
TEST_DIR="$3"

if [ -z "$BPF_DISASM" ] || [ -z "$BPF_ASM" ] || [ -z "$TEST_DIR" ]; then
    echo "Usage: $0 <bpf_disasm> <bpf_asm> <test_directory>"
    exit 1
fi

passed=0
failed=0
skipped=0
failures=""

for TEST_FILE in "$TEST_DIR"/*.data; do
    [ -f "$TEST_FILE" ] || continue

    # Step 1: Get original bytecode by disassembling the .data file
    ORIGINAL=$("$BPF_DISASM" --file "$TEST_FILE" 2>/dev/null)
    if [ -z "$ORIGINAL" ]; then
        skipped=$((skipped + 1))
        continue
    fi

    # Step 2: Extract just the assembly (strip line numbers)
    ASSEMBLY=$(echo "$ORIGINAL" | sed 's/^[[:space:]]*[0-9]*:[[:space:]]*//')

    # Step 3: Re-assemble
    REASSEMBLED_HEX=$(echo "$ASSEMBLY" | "$BPF_ASM" --stdin 2>/dev/null)
    if [ -z "$REASSEMBLED_HEX" ]; then
        failed=$((failed + 1))
        failures="$failures\n  FAIL (reassembly error): $(basename "$TEST_FILE")"
        continue
    fi

    # Step 4: Disassemble the reassembled output
    REASSEMBLED=$("$BPF_DISASM" --program "$REASSEMBLED_HEX" 2>/dev/null)

    # Step 5: Compare (strip line numbers for comparison)
    ORIGINAL_CLEAN=$(echo "$ORIGINAL" | sed 's/^[[:space:]]*[0-9]*:[[:space:]]*//')
    REASSEMBLED_CLEAN=$(echo "$REASSEMBLED" | sed 's/^[[:space:]]*[0-9]*:[[:space:]]*//')

    if [ "$ORIGINAL_CLEAN" = "$REASSEMBLED_CLEAN" ]; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        failures="$failures\n  FAIL (mismatch): $(basename "$TEST_FILE")"
    fi
done

echo ""
echo "Results: $passed passed, $failed failed, $skipped skipped"

if [ -n "$failures" ]; then
    echo ""
    echo "Failures:"
    echo -e "$failures"
fi

if [ $failed -gt 0 ]; then
    exit 1
fi
exit 0
