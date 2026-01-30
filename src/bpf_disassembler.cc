// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iomanip>
#include <sstream>
#include <unordered_map>
#include "bpf_disassembler.h"

// Helper function to format a register
static std::string
format_register(uint8_t reg)
{
    return "%r" + std::to_string(reg);
}

// Helper function to format an immediate value
static std::string
format_imm(int32_t imm)
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

// Helper function to format memory operand
static std::string
format_memory(uint8_t reg, int16_t offset)
{
    if (offset == 0) {
        return "[" + format_register(reg) + "]";
    } else {
        return "[" + format_register(reg) + (offset >= 0 ? "+" : "") + std::to_string(offset) + "]";
    }
}

// Helper function to format jump offset
static std::string
format_jump_offset(int16_t offset)
{
    if (offset >= 0) {
        return "+" + std::to_string(offset);
    } else {
        return std::to_string(offset);
    }
}

// Helper function to format raw bytes
static std::string
format_raw_bytes(const ebpf_inst& inst)
{
    std::ostringstream ss;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&inst);
    for (size_t i = 0; i < sizeof(ebpf_inst); i++) {
        if (i > 0) ss << " ";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::string
bpf_disassemble_inst(const ebpf_inst& inst)
{
    std::ostringstream result;
    uint8_t opcode_class = inst.opcode & EBPF_CLS_MASK;
    uint8_t opcode_alu = inst.opcode & EBPF_ALU_OP_MASK;
    uint8_t opcode_src = inst.opcode & EBPF_SRC_REG;
    uint8_t opcode_mode = inst.opcode & 0xf0;

    // Handle ALU/ALU64 operations
    if (opcode_class == EBPF_CLS_ALU || opcode_class == EBPF_CLS_ALU64) {
        bool is_64 = (opcode_class == EBPF_CLS_ALU64);
        std::string suffix = is_64 ? "" : "32";
        std::string mnemonic;

        switch (opcode_alu) {
        case EBPF_ALU_OP_ADD:
            mnemonic = "add";
            break;
        case EBPF_ALU_OP_SUB:
            mnemonic = "sub";
            break;
        case EBPF_ALU_OP_MUL:
            mnemonic = "mul";
            break;
        case EBPF_ALU_OP_DIV:
            if (inst.offset == 1) {
                mnemonic = "sdiv";
            } else {
                mnemonic = "div";
            }
            break;
        case EBPF_ALU_OP_OR:
            mnemonic = "or";
            break;
        case EBPF_ALU_OP_AND:
            mnemonic = "and";
            break;
        case EBPF_ALU_OP_LSH:
            mnemonic = "lsh";
            break;
        case EBPF_ALU_OP_RSH:
            mnemonic = "rsh";
            break;
        case EBPF_ALU_OP_NEG:
            result << "neg" << suffix << " " << format_register(inst.dst);
            return result.str();
        case EBPF_ALU_OP_MOD:
            if (inst.offset == 1) {
                mnemonic = "smod";
            } else {
                mnemonic = "mod";
            }
            break;
        case EBPF_ALU_OP_XOR:
            mnemonic = "xor";
            break;
        case EBPF_ALU_OP_MOV:
            if (inst.offset != 0) {
                result << "movsx" << suffix << inst.offset << " " << format_register(inst.dst) << ", "
                       << format_register(inst.src);
                return result.str();
            }
            mnemonic = "mov";
            break;
        case EBPF_ALU_OP_ARSH:
            mnemonic = "arsh";
            break;
        case EBPF_ALU_OP_END:
            if (opcode_src) {
                result << "be" << inst.imm << " " << format_register(inst.dst);
            } else if (is_64) {
                result << "swap" << inst.imm << " " << format_register(inst.dst);
            } else {
                result << "le" << inst.imm << " " << format_register(inst.dst);
            }
            return result.str();
        default:
            result << "unknown_alu";
            return result.str();
        }

        result << mnemonic << suffix << " " << format_register(inst.dst);
        if (opcode_src) {
            result << ", " << format_register(inst.src);
        } else {
            result << ", " << format_imm(inst.imm);
        }
        return result.str();
    }

    // Handle load/store operations
    if (opcode_class == EBPF_CLS_LD || opcode_class == EBPF_CLS_LDX || opcode_class == EBPF_CLS_ST ||
        opcode_class == EBPF_CLS_STX) {
        uint8_t size = inst.opcode & 0x18;
        uint8_t mode = inst.opcode & 0xe0;

        if (opcode_class == EBPF_CLS_LD && mode == EBPF_MODE_IMM && size == EBPF_SIZE_DW) {
            // lddw is a special case - it's a 2-instruction sequence
            result << "lddw " << format_register(inst.dst) << ", " << format_imm(inst.imm);
            return result.str();
        }

        if (opcode_class == EBPF_CLS_LDX) {
            std::string mnemonic = "ldx";
            if (mode == EBPF_MODE_MEMSX) {
                mnemonic = "ldxs";
            }
            switch (size) {
            case EBPF_SIZE_B:
                mnemonic += "b";
                break;
            case EBPF_SIZE_H:
                mnemonic += "h";
                break;
            case EBPF_SIZE_W:
                mnemonic += "w";
                break;
            case EBPF_SIZE_DW:
                mnemonic += "dw";
                break;
            }
            result << mnemonic << " " << format_register(inst.dst) << ", " << format_memory(inst.src, inst.offset);
            return result.str();
        }

        if (opcode_class == EBPF_CLS_ST) {
            std::string mnemonic = "st";
            switch (size) {
            case EBPF_SIZE_B:
                mnemonic += "b";
                break;
            case EBPF_SIZE_H:
                mnemonic += "h";
                break;
            case EBPF_SIZE_W:
                mnemonic += "w";
                break;
            case EBPF_SIZE_DW:
                mnemonic += "dw";
                break;
            }
            result << mnemonic << " " << format_memory(inst.dst, inst.offset) << ", " << format_imm(inst.imm);
            return result.str();
        }

        if (opcode_class == EBPF_CLS_STX) {
            // Check for atomic operations
            if (mode == EBPF_MODE_ATOMIC) {
                std::string width = (size == EBPF_SIZE_W) ? "32" : "";
                std::string op;
                bool has_fetch = false;

                if (inst.imm == EPBF_ATOMIC_OP_XCHG) {
                    op = "xchg";
                } else if (inst.imm == EBPF_ATOMIC_OP_CMPXCHG) {
                    op = "cmpxchg";
                } else {
                    has_fetch = (inst.imm & EBPF_ATOMIC_OP_FETCH) != 0;
                    uint8_t base_op = inst.imm & ~EBPF_ATOMIC_OP_FETCH;
                    switch (base_op) {
                    case EBPF_ALU_OP_ADD:
                        op = "add";
                        break;
                    case EBPF_ALU_OP_OR:
                        op = "or";
                        break;
                    case EBPF_ALU_OP_AND:
                        op = "and";
                        break;
                    case EBPF_ALU_OP_XOR:
                        op = "xor";
                        break;
                    default:
                        op = "unknown";
                        break;
                    }
                }

                result << "lock " << op << width << " ";
                if (has_fetch) {
                    result << "fetch ";
                }
                result << format_memory(inst.dst, inst.offset) << ", " << format_register(inst.src);
                return result.str();
            }

            // Regular store
            std::string mnemonic = "stx";
            switch (size) {
            case EBPF_SIZE_B:
                mnemonic += "b";
                break;
            case EBPF_SIZE_H:
                mnemonic += "h";
                break;
            case EBPF_SIZE_W:
                mnemonic += "w";
                break;
            case EBPF_SIZE_DW:
                mnemonic += "dw";
                break;
            }
            result << mnemonic << " " << format_memory(inst.dst, inst.offset) << ", " << format_register(inst.src);
            return result.str();
        }
    }

    // Handle jump operations
    if (opcode_class == EBPF_CLS_JMP || opcode_class == EBPF_CLS_JMP32) {
        bool is_32 = (opcode_class == EBPF_CLS_JMP32);
        std::string suffix = is_32 ? "32" : "";

        if (inst.opcode == EBPF_OP_EXIT) {
            result << "exit";
            return result.str();
        }

        if (inst.opcode == EBPF_OP_CALL) {
            result << "call ";
            if (inst.src == 0) {
                // Helper call
                if (opcode_src) {
                    result << "helper " << format_register(inst.dst);
                } else {
                    result << "helper " << format_imm(inst.imm);
                }
            } else if (inst.src == 1) {
                // Local call
                result << "local " << format_jump_offset(inst.imm);
            } else if (inst.src == 2) {
                // Runtime call
                result << "runtime " << format_imm(inst.imm);
            } else {
                result << "unknown " << format_imm(inst.imm);
            }
            return result.str();
        }

        if (inst.opcode == EBPF_OP_JA || inst.opcode == EBPF_OP_JA32) {
            if (is_32) {
                result << "ja32 " << format_jump_offset(inst.imm);
            } else {
                result << "ja " << format_jump_offset(inst.offset);
            }
            return result.str();
        }

        std::string mnemonic;
        switch (opcode_mode) {
        case EBPF_MODE_JEQ:
            mnemonic = "jeq";
            break;
        case EBPF_MODE_JGT:
            mnemonic = "jgt";
            break;
        case EBPF_MODE_JGE:
            mnemonic = "jge";
            break;
        case EBPF_MODE_JSET:
            mnemonic = "jset";
            break;
        case EBPF_MODE_JNE:
            mnemonic = "jne";
            break;
        case EBPF_MODE_JSGT:
            mnemonic = "jsgt";
            break;
        case EBPF_MODE_JSGE:
            mnemonic = "jsge";
            break;
        case EBPF_MODE_JLT:
            mnemonic = "jlt";
            break;
        case EBPF_MODE_JLE:
            mnemonic = "jle";
            break;
        case EBPF_MODE_JSLT:
            mnemonic = "jslt";
            break;
        case EBPF_MODE_JSLE:
            mnemonic = "jsle";
            break;
        default:
            mnemonic = "junknown";
            break;
        }

        result << mnemonic << suffix << " " << format_register(inst.dst) << ", ";
        if (opcode_src) {
            result << format_register(inst.src);
        } else {
            result << format_imm(inst.imm);
        }
        result << ", " << format_jump_offset(inst.offset);
        return result.str();
    }

    // Unknown instruction
    result << "unknown 0x" << std::hex << static_cast<int>(inst.opcode);
    return result.str();
}

void
bpf_disassembler(const std::vector<ebpf_inst>& instructions, std::ostream& output, bool show_raw)
{
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
            output << "lddw " << format_register(inst.dst) << ", 0x" << std::hex << imm64 << std::dec;

            if (show_raw) {
                output << " ; " << format_raw_bytes(inst);
            }
            output << std::endl;

            if (i + 1 < instructions.size()) {
                i++; // Skip the next instruction
            }
        } else {
            output << bpf_disassemble_inst(inst);

            if (show_raw) {
                output << " ; " << format_raw_bytes(inst);
            }
            output << std::endl;
        }
    }
}
