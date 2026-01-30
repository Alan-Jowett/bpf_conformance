#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

"""
Generate negative test cases for BPF instructions with non-zero unused fields.

Per the BPF spec: "Note that most instructions do not use all of the fields.
Unused fields must be set to zero."

This script generates .data test files that verify BPF runtimes reject
instructions with non-zero values in unused fields.
"""

import os
import struct
from dataclasses import dataclass
from typing import List, Set

# BPF instruction classes
EBPF_CLS_LD = 0x00
EBPF_CLS_LDX = 0x01
EBPF_CLS_ST = 0x02
EBPF_CLS_STX = 0x03
EBPF_CLS_ALU = 0x04
EBPF_CLS_JMP = 0x05
EBPF_CLS_JMP32 = 0x06
EBPF_CLS_ALU64 = 0x07

EBPF_SRC_IMM = 0x00
EBPF_SRC_REG = 0x08

# Memory modes
EBPF_MODE_IMM = 0x00
EBPF_MODE_MEM = 0x60
EBPF_MODE_MEMSX = 0x80
EBPF_MODE_ATOMIC = 0xc0

# Sizes
EBPF_SIZE_W = 0x00
EBPF_SIZE_H = 0x08
EBPF_SIZE_B = 0x10
EBPF_SIZE_DW = 0x18

# ALU operations
EBPF_ALU_OP_ADD = 0x00
EBPF_ALU_OP_SUB = 0x10
EBPF_ALU_OP_MUL = 0x20
EBPF_ALU_OP_DIV = 0x30
EBPF_ALU_OP_OR = 0x40
EBPF_ALU_OP_AND = 0x50
EBPF_ALU_OP_LSH = 0x60
EBPF_ALU_OP_RSH = 0x70
EBPF_ALU_OP_NEG = 0x80
EBPF_ALU_OP_MOD = 0x90
EBPF_ALU_OP_XOR = 0xa0
EBPF_ALU_OP_MOV = 0xb0
EBPF_ALU_OP_ARSH = 0xc0
EBPF_ALU_OP_END = 0xd0

# JMP modes
EBPF_MODE_JA = 0x00
EBPF_MODE_JEQ = 0x10
EBPF_MODE_JGT = 0x20
EBPF_MODE_JGE = 0x30
EBPF_MODE_JSET = 0x40
EBPF_MODE_JNE = 0x50
EBPF_MODE_JSGT = 0x60
EBPF_MODE_JSGE = 0x70
EBPF_MODE_CALL = 0x80
EBPF_MODE_EXIT = 0x90
EBPF_MODE_JLT = 0xa0
EBPF_MODE_JLE = 0xb0
EBPF_MODE_JSLT = 0xc0
EBPF_MODE_JSLE = 0xd0


@dataclass
class BpfInstruction:
    """Represents a BPF instruction."""
    name: str
    opcode: int
    # Which fields are used by this instruction
    uses_dst: bool = True
    uses_src: bool = False
    uses_offset: bool = False
    uses_imm: bool = False
    # Default valid values for fields
    default_dst: int = 0
    default_src: int = 0
    default_offset: int = 0
    default_imm: int = 0


def encode_instruction(opcode: int, dst: int, src: int, offset: int, imm: int) -> str:
    """Encode a BPF instruction as hex bytes."""
    # BPF instruction format: opcode(1) dst:src(1) offset(2) imm(4)
    dst_src = ((src & 0xf) << 4) | (dst & 0xf)
    packed = struct.pack('<BBhI', opcode, dst_src, offset, imm & 0xffffffff)
    return ' '.join(f'{b:02x}' for b in packed)


def encode_exit() -> str:
    """Encode an exit instruction."""
    return encode_instruction(EBPF_CLS_JMP | EBPF_MODE_EXIT, 0, 0, 0, 0)


def generate_test_file(name: str, raw_bytes: str, description: str) -> str:
    """Generate a .data test file content."""
    return f"""# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
# {description}
-- raw
{raw_bytes}
{encode_exit()}
-- error
"""


# Define instructions and their field usage
# Based on the BPF ISA spec and opcode_names.h

INSTRUCTIONS: List[BpfInstruction] = [
    # EXIT - all fields unused
    BpfInstruction("exit", EBPF_CLS_JMP | EBPF_MODE_EXIT,
                   uses_dst=False, uses_src=False, uses_offset=False, uses_imm=False),

    # JA (unconditional jump) - dst, src, imm unused
    BpfInstruction("ja", EBPF_CLS_JMP | EBPF_MODE_JA,
                   uses_dst=False, uses_src=False, uses_offset=True, uses_imm=False),

    # CALL - dst, offset unused (src used for call type, imm for helper id)
    BpfInstruction("call", EBPF_CLS_JMP | EBPF_MODE_CALL,
                   uses_dst=False, uses_src=True, uses_offset=False, uses_imm=True,
                   default_imm=0),

    # ALU IMM operations - src, offset unused
    BpfInstruction("add_imm", EBPF_CLS_ALU | EBPF_SRC_IMM | EBPF_ALU_OP_ADD,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=True,
                   default_imm=1),
    BpfInstruction("add64_imm", EBPF_CLS_ALU64 | EBPF_SRC_IMM | EBPF_ALU_OP_ADD,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=True,
                   default_imm=1),
    BpfInstruction("mov_imm", EBPF_CLS_ALU | EBPF_SRC_IMM | EBPF_ALU_OP_MOV,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=True,
                   default_imm=1),
    BpfInstruction("mov64_imm", EBPF_CLS_ALU64 | EBPF_SRC_IMM | EBPF_ALU_OP_MOV,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=True,
                   default_imm=1),

    # ALU REG operations - imm, offset unused
    BpfInstruction("add_reg", EBPF_CLS_ALU | EBPF_SRC_REG | EBPF_ALU_OP_ADD,
                   uses_dst=True, uses_src=True, uses_offset=False, uses_imm=False),
    BpfInstruction("add64_reg", EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD,
                   uses_dst=True, uses_src=True, uses_offset=False, uses_imm=False),
    BpfInstruction("mov_reg", EBPF_CLS_ALU | EBPF_SRC_REG | EBPF_ALU_OP_MOV,
                   uses_dst=True, uses_src=True, uses_offset=False, uses_imm=False),
    BpfInstruction("mov64_reg", EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV,
                   uses_dst=True, uses_src=True, uses_offset=False, uses_imm=False),

    # NEG - src, offset, imm unused
    BpfInstruction("neg", EBPF_CLS_ALU | EBPF_ALU_OP_NEG,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=False),
    BpfInstruction("neg64", EBPF_CLS_ALU64 | EBPF_ALU_OP_NEG,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=False),

    # Conditional jumps IMM - src unused
    BpfInstruction("jeq_imm", EBPF_CLS_JMP | EBPF_SRC_IMM | EBPF_MODE_JEQ,
                   uses_dst=True, uses_src=False, uses_offset=True, uses_imm=True),
    BpfInstruction("jgt_imm", EBPF_CLS_JMP | EBPF_SRC_IMM | EBPF_MODE_JGT,
                   uses_dst=True, uses_src=False, uses_offset=True, uses_imm=True),

    # Conditional jumps REG - imm unused
    BpfInstruction("jeq_reg", EBPF_CLS_JMP | EBPF_SRC_REG | EBPF_MODE_JEQ,
                   uses_dst=True, uses_src=True, uses_offset=True, uses_imm=False),
    BpfInstruction("jgt_reg", EBPF_CLS_JMP | EBPF_SRC_REG | EBPF_MODE_JGT,
                   uses_dst=True, uses_src=True, uses_offset=True, uses_imm=False),

    # LDX - imm unused
    BpfInstruction("ldxw", EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_W,
                   uses_dst=True, uses_src=True, uses_offset=True, uses_imm=False,
                   default_src=10, default_offset=-4),  # Use stack
    BpfInstruction("ldxdw", EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_DW,
                   uses_dst=True, uses_src=True, uses_offset=True, uses_imm=False,
                   default_src=10, default_offset=-8),

    # STX - imm unused
    BpfInstruction("stxw", EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_W,
                   uses_dst=True, uses_src=True, uses_offset=True, uses_imm=False,
                   default_dst=10, default_offset=-4),
    BpfInstruction("stxdw", EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_DW,
                   uses_dst=True, uses_src=True, uses_offset=True, uses_imm=False,
                   default_dst=10, default_offset=-8),

    # ST - src unused
    BpfInstruction("stw", EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_W,
                   uses_dst=True, uses_src=False, uses_offset=True, uses_imm=True,
                   default_dst=10, default_offset=-4, default_imm=0),
    BpfInstruction("stdw", EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_DW,
                   uses_dst=True, uses_src=False, uses_offset=True, uses_imm=True,
                   default_dst=10, default_offset=-8, default_imm=0),

    # Endianness - src, offset unused (imm specifies size: 16, 32, 64)
    BpfInstruction("le16", EBPF_CLS_ALU | EBPF_SRC_IMM | EBPF_ALU_OP_END,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=True,
                   default_imm=16),
    BpfInstruction("be16", EBPF_CLS_ALU | EBPF_SRC_REG | EBPF_ALU_OP_END,
                   uses_dst=True, uses_src=False, uses_offset=False, uses_imm=True,
                   default_imm=16),
]


def generate_tests(output_dir: str) -> int:
    """Generate all negative test files."""
    os.makedirs(output_dir, exist_ok=True)
    count = 0

    for inst in INSTRUCTIONS:
        # Test each unused field with a non-zero value
        unused_fields = []
        if not inst.uses_dst:
            unused_fields.append(('dst', 1, inst.default_dst))
        if not inst.uses_src:
            unused_fields.append(('src', 1, inst.default_src))
        if not inst.uses_offset:
            unused_fields.append(('offset', 1, inst.default_offset))
        if not inst.uses_imm:
            unused_fields.append(('imm', 1, inst.default_imm))

        for field_name, bad_value, default_value in unused_fields:
            # Build instruction with one bad field
            dst = bad_value if field_name == 'dst' else inst.default_dst
            src = bad_value if field_name == 'src' else inst.default_src
            offset = bad_value if field_name == 'offset' else inst.default_offset
            imm = bad_value if field_name == 'imm' else inst.default_imm

            raw = encode_instruction(inst.opcode, dst, src, offset, imm)
            desc = f"Test {inst.name} with non-zero {field_name} (unused field must be zero)"
            filename = f"unused-{inst.name}-{field_name}.data"
            filepath = os.path.join(output_dir, filename)

            content = generate_test_file(filename, raw, desc)
            with open(filepath, 'w', newline='\n') as f:
                f.write(content)
            count += 1
            print(f"Generated: {filename}")

    return count


if __name__ == '__main__':
    import sys
    output_dir = sys.argv[1] if len(sys.argv) > 1 else 'negative'
    count = generate_tests(output_dir)
    print(f"\nGenerated {count} test files in {output_dir}/")
