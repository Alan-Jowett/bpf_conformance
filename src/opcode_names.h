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

inline bool
needs_offset(uint8_t opcode)
{
    return opcode == 0x34 || opcode == 0x37 || opcode == 0x3c || opcode == 0x3f || opcode == 0x94 || opcode == 0x97 ||
           opcode == 0x9c || opcode == 0x9f || opcode == 0xbc || opcode == 0xbf;
}

class bpf_conformance_instruction_t
{
  public:
    bpf_conformance_instruction_t(
        bpf_conformance_test_cpu_version_t cpu_version,
        bpf_conformance_groups_t groups,
        uint8_t opcode,
        uint8_t src = 0,
        int32_t imm = 0,
        int16_t offset = 0)
    {
        this->cpu_version = cpu_version;
        this->groups = groups;
        this->opcode = opcode;
        this->src = src;
        this->imm = imm;
        this->offset = offset;
    }
    bpf_conformance_instruction_t(
        bpf_conformance_test_cpu_version_t cpu_version, bpf_conformance_groups_t groups, ebpf_inst inst)
    {
        opcode = inst.opcode;
        this->cpu_version = cpu_version;
        this->groups = groups;
        src = needs_src(opcode) ? inst.src : 0;
        imm = needs_imm(opcode) ? inst.imm : 0;
        offset = needs_offset(opcode) ? inst.offset : 0;
    }
    bpf_conformance_test_cpu_version_t cpu_version;
    bpf_conformance_groups_t groups;
    uint8_t opcode;
    uint8_t src = {};
    int32_t imm = {};
    int16_t offset = {};
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
        if (a.offset != b.offset) {
            return a.offset < b.offset;
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
    {(EBPF_CLS_JMP32 | 0x00), "EBPF_OP_JA32"},
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
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x00},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x04},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x05},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base32, 0x06},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x07},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x0c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x0f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x14},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x15},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x16},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x17},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x00},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x02},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x03},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x04},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x05},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x18, 0x06},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x1c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x1d},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x1e},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x1f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::packet, 0x20},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul32, 0x24},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x25},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x26},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul64, 0x27},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::packet, 0x28},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul32, 0x2c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x2d},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x2e},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul64, 0x2f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::packet, 0x30},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul32, 0x34, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul32, 0x34, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x35},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x36},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul64, 0x37, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul64, 0x37, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul32, 0x3c, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul32, 0x3c, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x3d},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x3e},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul64, 0x3f, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul64, 0x3f, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::packet, 0x40},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x44},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x45},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x46},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x47},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::packet, 0x48},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x4c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x4d},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x4e},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x4f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::packet, 0x50},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x54},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x55},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x56},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x57},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x5c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x5d},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x5e},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x5f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x61},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x62},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x63},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x64},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x65},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x66},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x67},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x69},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x6a},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x6b},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x6c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x6d},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x6e},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x6f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x71},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x72},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x73},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x74},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x75},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x76},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x77},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x79},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x7a},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x7b},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x7c},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x7d},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x7e},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0x7f},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x84},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x85, 0x00},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x85, 0x01},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0x85, 0x02},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x87},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::callx, 0x8d, 0x00},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul32, 0x94, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul32, 0x94, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0x95},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul64, 0x97, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul64, 0x97, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul32, 0x9c, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul32, 0x9c, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::divmul64, 0x9f, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::divmul64, 0x9f, 0x00, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xa4},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xa5},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xa6},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xa7},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xac},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xad},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xae},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xaf},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xb4, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xb5},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xb6},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xb7, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xbc, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base32, 0xbc, 0x00, 0x00, 0x08},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base32, 0xbc, 0x00, 0x00, 0x10},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xbd},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xbe},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xbf, 0x00, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base64, 0xbf, 0x00, 0x00, 0x08},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base64, 0xbf, 0x00, 0x00, 0x10},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base64, 0xbf, 0x00, 0x00, 0x20},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0x40},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0x41},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0x50},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0x51},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0xa0},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0xa1},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0xe1},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic32, 0xc3, 0x00, 0xf1},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xc4},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xc5},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xc6},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xc7},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xcc},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xcd},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xce},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xcf},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xd4, 0x00, 0x10},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xd4, 0x00, 0x20},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xd4, 0x00, 0x40},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xd5},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xd6},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base32, 0xd7, 0x00, 0x10},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base32, 0xd7, 0x00, 0x20},
    {bpf_conformance_test_cpu_version_t::v4, bpf_conformance_groups_t::base64, 0xd7, 0x00, 0x40},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0x00},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0x01},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0x40},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0x41},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0x50},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0x51},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0x50},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0xa0},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0xa1},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0xe1},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::atomic64, 0xdb, 0x00, 0xf1},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xdc, 0x00, 0x10},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base32, 0xdc, 0x00, 0x20},
    {bpf_conformance_test_cpu_version_t::v1, bpf_conformance_groups_t::base64, 0xdc, 0x00, 0x40},
    {bpf_conformance_test_cpu_version_t::v2, bpf_conformance_groups_t::base64, 0xdd},
    {bpf_conformance_test_cpu_version_t::v3, bpf_conformance_groups_t::base32, 0xde},
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
