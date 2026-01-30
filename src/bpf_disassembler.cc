// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <functional>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include "bpf_disassembler.h"

// The _bpf_disassembler class is a helper class for the bpf_disassembler.
typedef class _bpf_disassembler
{
  private:
    typedef std::string (_bpf_disassembler::*bpf_decode_t)(const ebpf_inst& inst);

    static std::string
    _format_register(uint8_t reg)
    {
        return "%r" + std::to_string(reg);
    }

    static std::string
    _format_imm(int32_t imm)
    {
        if (imm < 0 && imm != INT32_MIN) {
            return std::to_string(imm);
        } else if (imm >= -10 && imm <= 10) {
            return std::to_string(imm);
        } else {
            std::ostringstream ss;
            ss << "0x" << std::hex << static_cast<uint32_t>(imm);
            return ss.str();
        }
    }

    static std::string
    _format_memory(uint8_t reg, int16_t offset)
    {
        if (offset == 0) {
            return "[" + _format_register(reg) + "]";
        } else {
            return "[" + _format_register(reg) + (offset >= 0 ? "+" : "") + std::to_string(offset) + "]";
        }
    }

    static std::string
    _format_jump_offset(int32_t offset)
    {
        if (offset >= 0) {
            return "+" + std::to_string(offset);
        } else {
            return std::to_string(offset);
        }
    }

    static std::string
    _get_size_suffix(uint8_t size)
    {
        switch (size) {
        case EBPF_SIZE_B:
            return "b";
        case EBPF_SIZE_H:
            return "h";
        case EBPF_SIZE_W:
            return "w";
        case EBPF_SIZE_DW:
            return "dw";
        default:
            return "?";
        }
    }

    // ALU operation mnemonic map (opcode -> mnemonic)
    const std::unordered_map<int, std::string> _bpf_decode_alu_ops{
        {EBPF_ALU_OP_ADD, "add"},
        {EBPF_ALU_OP_SUB, "sub"},
        {EBPF_ALU_OP_MUL, "mul"},
        {EBPF_ALU_OP_DIV, "div"},
        {EBPF_ALU_OP_OR, "or"},
        {EBPF_ALU_OP_AND, "and"},
        {EBPF_ALU_OP_LSH, "lsh"},
        {EBPF_ALU_OP_RSH, "rsh"},
        {EBPF_ALU_OP_NEG, "neg"},
        {EBPF_ALU_OP_MOD, "mod"},
        {EBPF_ALU_OP_XOR, "xor"},
        {EBPF_ALU_OP_MOV, "mov"},
        {EBPF_ALU_OP_ARSH, "arsh"},
    };

    // Jump operation mnemonic map (opcode >> 4 -> mnemonic)
    const std::unordered_map<int, std::string> _bpf_decode_jmp_ops{
        {0x1, "jeq"},
        {0x2, "jgt"},
        {0x3, "jge"},
        {0x4, "jset"},
        {0x5, "jne"},
        {0x6, "jsgt"},
        {0x7, "jsge"},
        {0xa, "jlt"},
        {0xb, "jle"},
        {0xc, "jslt"},
        {0xd, "jsle"},
    };

    // Atomic operation mnemonic map
    const std::unordered_map<int, std::string> _bpf_decode_atomic_ops{
        {EBPF_ALU_OP_ADD, "add"},
        {EBPF_ALU_OP_OR, "or"},
        {EBPF_ALU_OP_AND, "and"},
        {EBPF_ALU_OP_XOR, "xor"},
    };

    std::string
    _decode_alu(const ebpf_inst& inst)
    {
        std::ostringstream result;
        uint8_t opcode_class = inst.opcode & EBPF_CLS_MASK;
        uint8_t opcode_alu = inst.opcode & EBPF_ALU_OP_MASK;
        uint8_t opcode_src = inst.opcode & EBPF_SRC_REG;
        bool is_64 = (opcode_class == EBPF_CLS_ALU64);
        std::string suffix = is_64 ? "" : "32";

        // Handle endianness conversion
        if (opcode_alu == EBPF_ALU_OP_END) {
            if (opcode_src) {
                result << "be" << inst.imm << " " << _format_register(inst.dst);
            } else if (is_64) {
                result << "swap" << inst.imm << " " << _format_register(inst.dst);
            } else {
                result << "le" << inst.imm << " " << _format_register(inst.dst);
            }
            return result.str();
        }

        // Handle NEG (single operand)
        if (opcode_alu == EBPF_ALU_OP_NEG) {
            result << "neg" << suffix << " " << _format_register(inst.dst);
            return result.str();
        }

        // Handle MOV with sign extension
        // Format: movsx<source_bits><dest_bits> where dest is 64 (no suffix) or 32
        if (opcode_alu == EBPF_ALU_OP_MOV && inst.offset != 0) {
            std::string dest_bits = is_64 ? "64" : "32";
            result << "movsx" << inst.offset << dest_bits << " " << _format_register(inst.dst) << ", "
                   << _format_register(inst.src);
            return result.str();
        }

        // Handle signed div/mod
        std::string mnemonic;
        if (opcode_alu == EBPF_ALU_OP_DIV) {
            mnemonic = (inst.offset == 1) ? "sdiv" : "div";
        } else if (opcode_alu == EBPF_ALU_OP_MOD) {
            mnemonic = (inst.offset == 1) ? "smod" : "mod";
        } else {
            auto iter = _bpf_decode_alu_ops.find(opcode_alu);
            mnemonic = (iter != _bpf_decode_alu_ops.end()) ? iter->second : "unknown_alu";
        }

        result << mnemonic << suffix << " " << _format_register(inst.dst) << ", ";
        if (opcode_src) {
            result << _format_register(inst.src);
        } else {
            result << _format_imm(inst.imm);
        }
        return result.str();
    }

    std::string
    _decode_ld(const ebpf_inst& inst)
    {
        // lddw is a special case - it's a 2-instruction sequence (handled in main disassembler loop for full imm64)
        return "lddw " + _format_register(inst.dst) + ", " + _format_imm(inst.imm);
    }

    std::string
    _decode_ldx(const ebpf_inst& inst)
    {
        uint8_t size = inst.opcode & 0x18;
        uint8_t mode = inst.opcode & 0xe0;

        std::string mnemonic = (mode == EBPF_MODE_MEMSX) ? "ldxs" : "ldx";
        mnemonic += _get_size_suffix(size);

        return mnemonic + " " + _format_register(inst.dst) + ", " + _format_memory(inst.src, inst.offset);
    }

    std::string
    _decode_st(const ebpf_inst& inst)
    {
        uint8_t size = inst.opcode & 0x18;
        std::string mnemonic = "st" + _get_size_suffix(size);

        return mnemonic + " " + _format_memory(inst.dst, inst.offset) + ", " + _format_imm(inst.imm);
    }

    std::string
    _decode_stx(const ebpf_inst& inst)
    {
        uint8_t size = inst.opcode & 0x18;
        uint8_t mode = inst.opcode & 0xe0;

        // Check for atomic operations
        if (mode == EBPF_MODE_ATOMIC) {
            return _decode_atomic(inst);
        }

        std::string mnemonic = "stx" + _get_size_suffix(size);
        return mnemonic + " " + _format_memory(inst.dst, inst.offset) + ", " + _format_register(inst.src);
    }

    std::string
    _decode_atomic(const ebpf_inst& inst)
    {
        std::ostringstream result;
        uint8_t size = inst.opcode & 0x18;
        std::string width = (size == EBPF_SIZE_W) ? "32" : "";

        result << "lock ";

        if (inst.imm == EPBF_ATOMIC_OP_XCHG) {
            result << "xchg" << width << " ";
        } else if (inst.imm == EBPF_ATOMIC_OP_CMPXCHG) {
            result << "cmpxchg" << width << " ";
        } else {
            bool has_fetch = (inst.imm & EBPF_ATOMIC_OP_FETCH) != 0;
            uint8_t base_op = inst.imm & ~EBPF_ATOMIC_OP_FETCH;

            auto iter = _bpf_decode_atomic_ops.find(base_op);
            std::string op = (iter != _bpf_decode_atomic_ops.end()) ? iter->second : "unknown";

            // Assembler expects: lock [fetch] <op><width> [mem], reg
            if (has_fetch) {
                result << "fetch ";
            }
            result << op << width << " ";
        }

        result << _format_memory(inst.dst, inst.offset) << ", " << _format_register(inst.src);
        return result.str();
    }

    std::string
    _decode_jmp(const ebpf_inst& inst)
    {
        std::ostringstream result;
        uint8_t opcode_class = inst.opcode & EBPF_CLS_MASK;
        uint8_t opcode_src = inst.opcode & EBPF_SRC_REG;
        bool is_32 = (opcode_class == EBPF_CLS_JMP32);
        std::string suffix = is_32 ? "32" : "";

        // Handle exit
        if (inst.opcode == EBPF_OP_EXIT) {
            return "exit";
        }

        // Handle call (both immediate and register variants)
        if ((inst.opcode & ~EBPF_SRC_REG) == EBPF_OP_CALL) {
            return _decode_call(inst);
        }

        // Handle unconditional jump
        if (inst.opcode == EBPF_OP_JA || inst.opcode == EBPF_OP_JA32) {
            if (is_32) {
                return "ja32 " + _format_jump_offset(inst.imm);
            } else {
                return "ja " + _format_jump_offset(inst.offset);
            }
        }

        // Handle conditional jumps
        uint8_t jmp_op = (inst.opcode >> 4) & 0x0f;
        auto iter = _bpf_decode_jmp_ops.find(jmp_op);
        std::string mnemonic = (iter != _bpf_decode_jmp_ops.end()) ? iter->second : "junknown";

        result << mnemonic << suffix << " " << _format_register(inst.dst) << ", ";
        if (opcode_src) {
            result << _format_register(inst.src);
        } else {
            result << _format_imm(inst.imm);
        }
        result << ", " << _format_jump_offset(inst.offset);
        return result.str();
    }

    std::string
    _decode_call(const ebpf_inst& inst)
    {
        std::ostringstream result;
        uint8_t opcode_src = inst.opcode & EBPF_SRC_REG;

        result << "call ";
        if (inst.src == 0) {
            // Helper call
            if (opcode_src) {
                result << "helper " << _format_register(inst.dst);
            } else {
                result << "helper " << _format_imm(inst.imm);
            }
        } else if (inst.src == 1) {
            // Local call
            result << "local " << _format_jump_offset(inst.imm);
        } else if (inst.src == 2) {
            // Runtime call
            result << "runtime " << _format_imm(inst.imm);
        } else {
            result << "unknown " << _format_imm(inst.imm);
        }
        return result.str();
    }

    std::string
    _decode_unknown(const ebpf_inst& inst)
    {
        std::ostringstream result;
        result << "unknown 0x" << std::hex << static_cast<int>(inst.opcode);
        return result.str();
    }

    // Dispatch table: maps instruction class to decode handler
    const std::unordered_map<int, bpf_decode_t> _bpf_decode_class_map{
        {EBPF_CLS_LD, &_bpf_disassembler::_decode_ld},
        {EBPF_CLS_LDX, &_bpf_disassembler::_decode_ldx},
        {EBPF_CLS_ST, &_bpf_disassembler::_decode_st},
        {EBPF_CLS_STX, &_bpf_disassembler::_decode_stx},
        {EBPF_CLS_ALU, &_bpf_disassembler::_decode_alu},
        {EBPF_CLS_JMP, &_bpf_disassembler::_decode_jmp},
        {EBPF_CLS_JMP32, &_bpf_disassembler::_decode_jmp},
        {EBPF_CLS_ALU64, &_bpf_disassembler::_decode_alu},
    };

  public:
    _bpf_disassembler() = default;
    ~_bpf_disassembler() = default;

    std::string
    disassemble_inst(const ebpf_inst& inst)
    {
        uint8_t opcode_class = inst.opcode & EBPF_CLS_MASK;

        auto iter = _bpf_decode_class_map.find(opcode_class);
        if (iter != _bpf_decode_class_map.end()) {
            return (this->*(iter->second))(inst);
        }

        return _decode_unknown(inst);
    }
} bpf_disassembler_t;

// Helper function to format raw bytes
static std::string
format_raw_bytes(const ebpf_inst& inst)
{
    std::ostringstream ss;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&inst);
    for (size_t i = 0; i < sizeof(ebpf_inst); i++) {
        if (i > 0)
            ss << " ";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::string
bpf_disassemble_inst(const ebpf_inst& inst)
{
    bpf_disassembler_t disassembler;
    return disassembler.disassemble_inst(inst);
}

void
bpf_disassembler(const std::vector<ebpf_inst>& instructions, std::ostream& output, bool show_raw)
{
    bpf_disassembler_t disassembler;

    for (size_t i = 0; i < instructions.size(); i++) {
        const ebpf_inst& inst = instructions[i];
        output << std::setw(4) << std::setfill(' ') << std::dec << i << ": ";

        // Handle lddw specially to show the full 64-bit immediate
        if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_LD && (inst.opcode & 0x18) == EBPF_SIZE_DW &&
            (inst.opcode & 0xe0) == EBPF_MODE_IMM) {
            uint64_t imm64 = static_cast<uint32_t>(inst.imm);
            if (i + 1 < instructions.size()) {
                imm64 |= (static_cast<uint64_t>(static_cast<uint32_t>(instructions[i + 1].imm)) << 32);
            }
            output << "lddw %r" << static_cast<int>(inst.dst) << ", 0x" << std::hex << imm64 << std::dec;

            if (show_raw) {
                output << " ; " << format_raw_bytes(inst);
            }
            output << std::endl;

            if (i + 1 < instructions.size()) {
                i++; // Skip the next instruction
            }
        } else {
            output << disassembler.disassemble_inst(inst);

            if (show_raw) {
                output << " ; " << format_raw_bytes(inst);
            }
            output << std::endl;
        }
    }
}
