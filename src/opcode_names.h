// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <charconv>
#include <map>
#include <string>
#include <set>
#include "ebpf.h"

inline bool
needs_src(uint8_t opcode)
{
    return opcode == 0x18 || opcode == 0x85;
}

inline bool
needs_imm(uint8_t opcode)
{
    return opcode == 0xc3 || opcode == 0xd4 || opcode == 0xdb || opcode == 0xdc;
}

class bpf_conformance_instruction_t
{
  public:
    bpf_conformance_instruction_t(uint8_t opcode, uint8_t src = 0, uint32_t imm = 0)
    {
        this->opcode = opcode;
        this->src = src;
        this->imm = imm;
    }
    bpf_conformance_instruction_t(ebpf_inst inst)
    {
        opcode = inst.opcode;
        src = needs_src(opcode) ? inst.src : 0;
        imm = needs_imm(opcode) ? inst.imm : 0;
    }
    uint8_t opcode;
    uint8_t src = {};
    uint32_t imm = {};
};

struct InstCmp
{
    bool
    operator()(const bpf_conformance_instruction_t& a, const bpf_conformance_instruction_t& b) const
    {
        if (a.opcode != b.opcode) {
            return a.opcode < b.opcode;
        }
        if (a.src != b.src) {
            return a.src < b.src;
        }
        return a.imm < b.imm;
    }
};

/**
 * @brief Map of opcode names.
 */
static const std::map<uint8_t, std::string> opcode_names = {
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x00), "EBPF_OP_ADD_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x00), "EBPF_OP_ADD_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x00), "EBPF_OP_ADD64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x00), "EBPF_OP_ADD64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x50), "EBPF_OP_AND_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x50), "EBPF_OP_AND_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x50), "EBPF_OP_AND64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x50), "EBPF_OP_AND64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0xc0), "EBPF_OP_ARSH_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0xc0), "EBPF_OP_ARSH_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0xc0), "EBPF_OP_ARSH64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0xc0), "EBPF_OP_ARSH64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0xd0), "EBPF_OP_BE"},
    {(EBPF_CLS_JMP | 0x80), "EBPF_OP_CALL"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x30), "EBPF_OP_DIV_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x30), "EBPF_OP_DIV_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x30), "EBPF_OP_DIV64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x30), "EBPF_OP_DIV64_REG"},
    {(EBPF_CLS_JMP | 0x90), "EBPF_OP_EXIT"},
    {(EBPF_CLS_JMP | 0x00), "EBPF_OP_JA"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0x10), "EBPF_OP_JEQ_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0x10), "EBPF_OP_JEQ_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0x10), "EBPF_OP_JEQ32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0x10), "EBPF_OP_JEQ32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0x30), "EBPF_OP_JGE_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0x30), "EBPF_OP_JGE_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0x30), "EBPF_OP_JGE32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0x30), "EBPF_OP_JGE32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0x20), "EBPF_OP_JGT_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0x20), "EBPF_OP_JGT_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0x20), "EBPF_OP_JGT32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0x20), "EBPF_OP_JGT32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0xb0), "EBPF_OP_JLE_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0xb0), "EBPF_OP_JLE_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0xb0), "EBPF_OP_JLE32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0xb0), "EBPF_OP_JLE32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0xa0), "EBPF_OP_JLT_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0xa0), "EBPF_OP_JLT_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0xa0), "EBPF_OP_JLT32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0xa0), "EBPF_OP_JLT32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0x50), "EBPF_OP_JNE_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0x50), "EBPF_OP_JNE_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0x50), "EBPF_OP_JNE32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0x50), "EBPF_OP_JNE32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0x40), "EBPF_OP_JSET_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0x40), "EBPF_OP_JSET_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0x40), "EBPF_OP_JSET32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0x40), "EBPF_OP_JSET32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0x70), "EBPF_OP_JSGE_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0x70), "EBPF_OP_JSGE_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0x70), "EBPF_OP_JSGE32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0x70), "EBPF_OP_JSGE32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0x60), "EBPF_OP_JSGT_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0x60), "EBPF_OP_JSGT_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0x60), "EBPF_OP_JSGT32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0x60), "EBPF_OP_JSGT32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0xd0), "EBPF_OP_JSLE_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0xd0), "EBPF_OP_JSLE_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0xd0), "EBPF_OP_JSLE32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0xd0), "EBPF_OP_JSLE32_REG"},
    {(EBPF_CLS_JMP | EBPF_SRC_IMM | 0xc0), "EBPF_OP_JSLT_IMM"},
    {(EBPF_CLS_JMP | EBPF_SRC_REG | 0xc0), "EBPF_OP_JSLT_REG"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_IMM | 0xc0), "EBPF_OP_JSLT32_IMM"},
    {(EBPF_CLS_JMP32 | EBPF_SRC_REG | 0xc0), "EBPF_OP_JSLT32_REG"},
    {(EBPF_CLS_LD | EBPF_MODE_IMM | EBPF_SIZE_DW), "EBPF_OP_LDDW"},
    {(EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_B), "EBPF_OP_LDXB"},
    {(EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_DW), "EBPF_OP_LDXDW"},
    {(EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_H), "EBPF_OP_LDXH"},
    {(EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_W), "EBPF_OP_LDXW"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0xd0), "EBPF_OP_LE"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x60), "EBPF_OP_LSH_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x60), "EBPF_OP_LSH_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x60), "EBPF_OP_LSH64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x60), "EBPF_OP_LSH64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x90), "EBPF_OP_MOD_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x90), "EBPF_OP_MOD_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x90), "EBPF_OP_MOD64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x90), "EBPF_OP_MOD64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0xb0), "EBPF_OP_MOV_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0xb0), "EBPF_OP_MOV_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0xb0), "EBPF_OP_MOV64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0xb0), "EBPF_OP_MOV64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x20), "EBPF_OP_MUL_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x20), "EBPF_OP_MUL_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x20), "EBPF_OP_MUL64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x20), "EBPF_OP_MUL64_REG"},
    {(EBPF_CLS_ALU | 0x80), "EBPF_OP_NEG"},
    {(EBPF_CLS_ALU64 | 0x80), "EBPF_OP_NEG64"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x40), "EBPF_OP_OR_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x40), "EBPF_OP_OR_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x40), "EBPF_OP_OR64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x40), "EBPF_OP_OR64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x70), "EBPF_OP_RSH_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x70), "EBPF_OP_RSH_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x70), "EBPF_OP_RSH64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x70), "EBPF_OP_RSH64_REG"},
    {(EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_B), "EBPF_OP_STB"},
    {(EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_DW), "EBPF_OP_STDW"},
    {(EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_H), "EBPF_OP_STH"},
    {(EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_W), "EBPF_OP_STW"},
    {(EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_B), "EBPF_OP_STXB"},
    {(EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_DW), "EBPF_OP_STXDW"},
    {(EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_H), "EBPF_OP_STXH"},
    {(EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_W), "EBPF_OP_STXW"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0x10), "EBPF_OP_SUB_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0x10), "EBPF_OP_SUB_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x10), "EBPF_OP_SUB64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x10), "EBPF_OP_SUB64_REG"},
    {(EBPF_CLS_ALU | EBPF_SRC_IMM | 0xa0), "EBPF_OP_XOR_IMM"},
    {(EBPF_CLS_ALU | EBPF_SRC_REG | 0xa0), "EBPF_OP_XOR_REG"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0xa0), "EBPF_OP_XOR64_IMM"},
    {(EBPF_CLS_ALU64 | EBPF_SRC_REG | 0xa0), "EBPF_OP_XOR64_REG"},
    {0xc3, "EPBF_ATOMIC_32"},
    {0xdb, "EPBF_ATOMIC_64"},
};

// List of opcodes from the BPF ISA spec.
static const std::set<bpf_conformance_instruction_t, InstCmp> instructions_from_spec = {
    0x00,
    0x04,
    0x05,
    0x07,
    0x0c,
    0x0f,
    0x14,
    0x15,
    0x16,
    0x17,
    {0x18, 0x00},
    {0x18, 0x01},
    {0x18, 0x02},
    {0x18, 0x03},
    {0x18, 0x04},
    {0x18, 0x05},
    {0x18, 0x06},
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    0x24,
    0x25,
    0x26,
    0x27,
    0x2c,
    0x2d,
    0x2e,
    0x2f,
    0x34,
    0x35,
    0x36,
    0x37,
    0x3c,
    0x3d,
    0x3e,
    0x3f,
    0x44,
    0x45,
    0x46,
    0x47,
    0x4c,
    0x4d,
    0x4e,
    0x4f,
    0x54,
    0x55,
    0x56,
    0x57,
    0x5c,
    0x5d,
    0x5e,
    0x5f,
    0x61,
    0x62,
    0x63,
    0x64,
    0x65,
    0x66,
    0x67,
    0x69,
    0x6a,
    0x6b,
    0x6c,
    0x6d,
    0x6e,
    0x6f,
    0x71,
    0x72,
    0x73,
    0x74,
    0x75,
    0x76,
    0x77,
    0x79,
    0x7a,
    0x7b,
    0x7c,
    0x7d,
    0x7e,
    0x7f,
    0x84,
    {0x85, 0x00},
    {0x85, 0x01},
    {0x85, 0x02},
    0x87,
    0x94,
    0x95,
    0x97,
    0x9c,
    0x9f,
    0xa4,
    0xa5,
    0xa6,
    0xa7,
    0xac,
    0xad,
    0xae,
    0xaf,
    0xb4,
    0xb5,
    0xb7,
    0xbc,
    0xbd,
    0xbe,
    0xbf,
    {0xc3, 0x00, 0x00},
    {0xc3, 0x00, 0x01},
    {0xc3, 0x00, 0x40},
    {0xc3, 0x00, 0x41},
    {0xc3, 0x00, 0x50},
    {0xc3, 0x00, 0x51},
    {0xc3, 0x00, 0xa0},
    {0xc3, 0x00, 0xa1},
    {0xc3, 0x00, 0xe1},
    {0xc3, 0x00, 0xf1},
    0xc4,
    0xc5,
    0xc6,
    0xc7,
    0xcc,
    0xcd,
    0xce,
    0xcf,
    {0xd4, 0x00, 0x10},
    {0xd4, 0x00, 0x20},
    {0xd4, 0x00, 0x40},
    0xd5,
    0xd6,
    {0xdb, 0x00, 0x00},
    {0xdb, 0x00, 0x01},
    {0xdb, 0x00, 0x40},
    {0xdb, 0x00, 0x41},
    {0xdb, 0x00, 0x50},
    {0xdb, 0x00, 0x51},
    {0xdb, 0x00, 0x50},
    {0xdb, 0x00, 0xa0},
    {0xdb, 0x00, 0xa1},
    {0xdb, 0x00, 0xe1},
    {0xdb, 0x00, 0xf1},
    {0xdc, 0x00, 0x10},
    {0xdc, 0x00, 0x20},
    {0xdc, 0x00, 0x40},
    0xdd,
    0xde,
};

/**
 * @brief Get the display name of an instruction.
 *
 * @param[in] instruction Instruction to look up.
 * @return Human readable name of the instruction.
 */
static std::string
instruction_to_name(bpf_conformance_instruction_t instruction)
{
    std::stringstream ss;
    ss << "0x" << std::hex << (uint32_t)instruction.opcode << " ";
    if (needs_src(instruction.opcode))
        ss << "src 0x" << (uint32_t)instruction.src << " ";
    if (needs_imm(instruction.opcode))
        ss << "imm 0x" << instruction.imm << " ";

    auto it = opcode_names.find(instruction.opcode);
    if (it != opcode_names.end())
        ss << it->second;
    else {
        std::string str;
        str.resize(16);

        std::to_chars(&str[0], &str[str.size()], instruction.opcode, 16);

        ss << str;
    }

    return ss.str();
}
