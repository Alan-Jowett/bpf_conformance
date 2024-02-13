// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <array>
#include <functional>
#include <optional>
#include <unordered_map>
#include <variant>
#include <sstream>

#include "bpf_assembler.h"

// The _bpf_assembler class is a helper class for the bpf_assembler.
typedef class _bpf_assembler
{

  private:
    typedef std::variant<ebpf_inst, std::array<ebpf_inst, 2>> bpf_encode_result_t;

    typedef bpf_encode_result_t (_bpf_assembler::*bpf_encode_t)(
        const std::string& mnemonic, const std::vector<std::string>& operands);

    const std::unordered_map<std::string, int> _bpf_encode_register_map{
        {"%r0", 0},
        {"%r1", 1},
        {"%r2", 2},
        {"%r3", 3},
        {"%r4", 4},
        {"%r5", 5},
        {"%r6", 6},
        {"%r7", 7},
        {"%r8", 8},
        {"%r9", 9},
        {"%r10", 10},
        // Add fake registers to support negative tests.
        {"%r11", 11},
        {"%r12", 12},
        {"%r13", 13},
        {"%r14", 14},
        {"%r15", 15},
    };

    const std::unordered_map<std::string, int> _bpf_encode_alu_ops{
        {"add", 0x0},
        {"sub", 0x1},
        {"mul", 0x2},
        {"div", 0x3},
        {"sdiv", 0x3},
        {"or", 0x4},
        {"and", 0x5},
        {"lsh", 0x6},
        {"rsh", 0x7},
        {"neg", 0x8},
        {"mod", 0x9},
        {"smod", 0x9},
        {"xor", 0xa},
        {"mov", 0xb},
        {"movsx", 0xb},
        {"arsh", 0xc},
        {"le", 0xd},
        {"be", 0xd},
        {"swap", 0xd},
    };

    const std::unordered_map<std::string, int> _bpf_encode_jmp_ops{
        {"jeq", 0x1},
        {"jgt", 0x2},
        {"jge", 0x3},
        {"jset", 0x4},
        {"jne", 0x5},
        {"jsgt", 0x6},
        {"jsge", 0x7},
        {"jlt", 0xa},
        {"jle", 0xb},
        {"jslt", 0xc},
        {"jsle", 0xd},
    };

    // Labels discovered while parsing the assembly code.
    std::unordered_map<std::string, size_t> _labels{};

    // Vector of the same size as the assembly code, containing the label to
    // jump to.
    std::vector<std::optional<std::string>> _jump_instructions{};

    uint64_t
    _decode_imm64(const std::string& str)
    {
        if (str.find("0x") == std::string::npos) {
            return std::stoull(str);
        } else {
            return std::stoull(str, nullptr, 16);
        }
    }

    uint32_t
    _decode_imm32(const std::string& str)
    {
        if (str.find("0x") == std::string::npos) {
            return static_cast<uint32_t>(std::stoull(str));
        } else {
            return static_cast<uint32_t>(std::stoull(str, nullptr, 16));
        }
    }

    uint16_t
    _decode_offset(const std::string& str)
    {
        if (str.find("0x") == std::string::npos) {
            return static_cast<uint16_t>(std::stoull(str));
        } else {
            return static_cast<uint16_t>(std::stoull(str, nullptr, 16));
        }
    }

    uint16_t
    _decode_jump_target(const std::string& str)
    {
        if (str.starts_with("+") || str.starts_with("-")) {
            return _decode_offset(str);
        } else {
            _jump_instructions.back() = {str};
            return 0;
        }
    }

    uint8_t
    _decode_register(const std::string& register_name)
    {
        auto reg = _bpf_encode_register_map.find(register_name);
        if (reg == _bpf_encode_register_map.end()) {
            throw std::runtime_error(std::string("Invalid register: ") + register_name);
        }
        return static_cast<uint8_t>(reg->second);
    }

    std::tuple<uint8_t, uint16_t>
    _decode_register_and_offset(const std::string& operand)
    {
        auto reg_start = operand.find('[');
        auto reg_end = operand.find('+');
        reg_end = (reg_end != std::string::npos) ? reg_end : operand.find('-');
        reg_end = (reg_end != std::string::npos) ? reg_end : operand.find(']');

        if (reg_start == std::string::npos || reg_end == std::string::npos) {
            throw std::runtime_error(std::string("Failed to decode register and offset: ") + operand);
        }

        if (operand.substr(reg_end).starts_with(']')) {
            return std::make_tuple<uint8_t, uint16_t>(
                _decode_register(operand.substr(reg_start + 1, reg_end - reg_start - 1)), 0);
        } else {
            return std::make_tuple<uint8_t, uint16_t>(
                _decode_register(operand.substr(reg_start + 1, reg_end - reg_start - 1)),
                _decode_offset(operand.substr(reg_end)));
        }
    }

    bpf_encode_result_t
    _encode_ld([[maybe_unused]] const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        std::array<ebpf_inst, 2> inst{};
        // Issue: https://github.com/Alan-Jowett/bpf_conformance/issues/59
        // Add support for other 64-bit immediate values.
        inst[0].opcode = EBPF_OP_LDDW;
        inst[0].dst = _decode_register(operands[0]);
        uint64_t immediate = _decode_imm64(operands[1]);
        inst[0].imm = static_cast<uint32_t>(immediate);
        inst[1].imm = static_cast<uint32_t>(immediate >> 32);

        return inst;
    }

    bpf_encode_result_t
    _encode_ldx(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        inst.dst = _decode_register(operands[0]);
        auto [src, offset] = _decode_register_and_offset(operands[1]);
        inst.src = src;
        inst.offset = offset;
        if (mnemonic == "ldxb") {
            inst.opcode = EBPF_OP_LDXB;
        } else if (mnemonic == "ldxdw") {
            inst.opcode = EBPF_OP_LDXDW;
        } else if (mnemonic == "ldxh") {
            inst.opcode = EBPF_OP_LDXH;
        } else if (mnemonic == "ldxw") {
            inst.opcode = EBPF_OP_LDXW;
        }

        return inst;
    }

    bpf_encode_result_t
    _encode_st(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        auto [dst, offset] = _decode_register_and_offset(operands[0]);
        inst.dst = dst;
        inst.offset = offset;
        if (mnemonic == "stb") {
            inst.opcode = EBPF_OP_STB;
        } else if (mnemonic == "stdw") {
            inst.opcode = EBPF_OP_STDW;
        } else if (mnemonic == "sth") {
            inst.opcode = EBPF_OP_STH;
        } else if (mnemonic == "stw") {
            inst.opcode = EBPF_OP_STW;
        }
        inst.imm = _decode_imm32(operands[1]);
        return inst;
    }

    bpf_encode_result_t
    _encode_stx(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        auto [dst, offset] = _decode_register_and_offset(operands[0]);
        inst.dst = dst;
        inst.offset = offset;
        inst.src = _decode_register(operands[1]);
        if (mnemonic == "stxb") {
            inst.opcode = EBPF_OP_STXB;
        } else if (mnemonic == "stxdw") {
            inst.opcode = EBPF_OP_STXDW;
        } else if (mnemonic == "stxh") {
            inst.opcode = EBPF_OP_STXH;
        } else if (mnemonic == "stxw") {
            inst.opcode = EBPF_OP_STXW;
        }

        return inst;
    }

    bpf_encode_result_t
    _encode_alu(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        std::string alu_op;
        if (mnemonic.starts_with("be")) {
            inst.opcode = EBPF_OP_BE;
            inst.dst = _decode_register(operands[0]);
            inst.imm = _decode_imm32(mnemonic.substr(2));
            return inst;
        } else if (mnemonic.starts_with("le")) {
            inst.opcode = EBPF_OP_LE;
            inst.dst = _decode_register(operands[0]);
            inst.imm = _decode_imm32(mnemonic.substr(2));
            return inst;
        } else if (mnemonic.starts_with("swap")) {
            inst.opcode = EBPF_OP_SWAP;
            inst.dst = _decode_register(operands[0]);
            inst.imm = _decode_imm32(mnemonic.substr(4));
            return inst;
        }
        if (mnemonic.starts_with("sdiv") || mnemonic.starts_with("smod")) {
            inst.offset = 1;
        }

        if (mnemonic.ends_with("32")) {
            inst.opcode |= EBPF_CLS_ALU;
            alu_op = mnemonic.substr(0, mnemonic.size() - 2);
        } else if (mnemonic.ends_with("64")) {
            inst.opcode |= EBPF_CLS_ALU64;
            alu_op = mnemonic.substr(0, mnemonic.size() - 2);
        } else {
            inst.opcode |= EBPF_CLS_ALU64;
            alu_op = mnemonic;
        }
        if (alu_op.starts_with("movsx")) {
            inst.offset = _decode_offset(alu_op.substr(5));
            alu_op = "movsx";
        }
        auto iter = _bpf_encode_alu_ops.find(alu_op);
        // It is not possible to reach here with no match.
        inst.opcode |= iter->second << 4;

        inst.dst = _decode_register(operands[0]);

        if (operands.size() == 2) {
            if (operands[1].starts_with('%')) {
                inst.opcode |= EBPF_SRC_REG;
                inst.src = _decode_register(operands[1]);
            } else {
                inst.opcode |= EBPF_SRC_IMM;
                inst.imm = _decode_imm32(operands[1]);
            }
        }

        return inst;
    }

    bpf_encode_result_t
    _encode_jmp(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (mnemonic == "ja") {
            inst.opcode = EBPF_CLS_JMP;
            inst.offset = _decode_jump_target(operands[0]);
        } else if (mnemonic == "ja32") {
            inst.opcode = EBPF_CLS_JMP32;
            inst.imm = _decode_jump_target(operands[0]);
        } else if (mnemonic == "exit") {
            inst.opcode = EBPF_OP_EXIT;
        } else if (mnemonic == "call") {
            inst.opcode = EBPF_OP_CALL;
            auto mode = operands[0];
            auto target = operands[1];
            // Mode determines if this is a helper function, a local call, or a call to a runtime function.
            if (mode == "helper") {
                if (target.starts_with('%')) {
                    inst.opcode |= EBPF_SRC_REG;
                    inst.dst = _decode_register(target);
                } else {
                    inst.opcode |= EBPF_SRC_IMM;
                    inst.imm = _decode_imm32(target);
                }
                inst.src = 0;
            } else if (mode == "local") {
                inst.imm = _decode_jump_target(target);
                inst.src = 1;
            } else if (mode == "runtime") {
                inst.imm = _decode_imm32(target);
                inst.src = 2;
            } else {
                throw std::runtime_error("Invalid call mode");
            }
        } else {
            mnemonic.ends_with("32") ? inst.opcode = EBPF_CLS_JMP32 : inst.opcode = EBPF_CLS_JMP;
            auto iter =
                _bpf_encode_jmp_ops.find(mnemonic.ends_with("32") ? mnemonic.substr(0, mnemonic.size() - 2) : mnemonic);
            // It is not possible to reach here with no match.
            inst.opcode |= iter->second << 4;
            inst.dst = _decode_register(operands[0]);
            if (operands[1].starts_with('%')) {
                inst.opcode |= EBPF_SRC_REG;
                inst.src = _decode_register(operands[1]);
            } else {
                inst.opcode |= EBPF_SRC_IMM;
                inst.imm = _decode_imm32(operands[1]);
            }
            inst.offset = _decode_jump_target(operands[2]);
        }
        return inst;
    }

    bpf_encode_result_t
    _encode_atomic_add(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (mnemonic.ends_with("32")) {
            inst.opcode = EBPF_OP_ATOMIC32_STORE;
        } else {
            inst.opcode = EBPF_OP_ATOMIC_STORE;
        }
        auto [dst, offset] = _decode_register_and_offset(operands[1]);
        inst.dst = dst;
        inst.offset = offset;
        inst.src = _decode_register(operands[2]);
        inst.imm = EBPF_ALU_OP_ADD;
        // Set fetch bit if fetch is the first operand.
        if (operands[0] == "fetch") {
            inst.imm |= EBPF_ATOMIC_OP_FETCH;
        }
        return inst;
    }

    bpf_encode_result_t
    _encode_atomic_and(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (mnemonic.ends_with("32")) {
            inst.opcode = EBPF_OP_ATOMIC32_STORE;
        } else {
            inst.opcode = EBPF_OP_ATOMIC_STORE;
        }
        auto [dst, offset] = _decode_register_and_offset(operands[1]);
        inst.dst = dst;
        inst.offset = offset;
        inst.src = _decode_register(operands[2]);
        inst.imm = EBPF_ALU_OP_AND;
        // Set fetch bit if fetch is the first operand.
        if (operands[0] == "fetch") {
            inst.imm |= EBPF_ATOMIC_OP_FETCH;
        }
        return inst;
    }

    bpf_encode_result_t
    _encode_atomic_or(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (mnemonic.ends_with("32")) {
            inst.opcode = EBPF_OP_ATOMIC32_STORE;
        } else {
            inst.opcode = EBPF_OP_ATOMIC_STORE;
        }
        auto [dst, offset] = _decode_register_and_offset(operands[1]);
        inst.dst = dst;
        inst.offset = offset;
        inst.src = _decode_register(operands[2]);
        inst.imm = EBPF_ALU_OP_OR;
        // Set fetch bit if fetch is the first operand.
        if (operands[0] == "fetch") {
            inst.imm |= EBPF_ATOMIC_OP_FETCH;
        }
        return inst;
    }

    bpf_encode_result_t
    _encode_atomic_xor(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (mnemonic.ends_with("32")) {
            inst.opcode = EBPF_OP_ATOMIC32_STORE;
        } else {
            inst.opcode = EBPF_OP_ATOMIC_STORE;
        }
        auto [dst, offset] = _decode_register_and_offset(operands[1]);
        inst.dst = dst;
        inst.offset = offset;
        inst.src = _decode_register(operands[2]);
        inst.imm = EBPF_ALU_OP_XOR;
        // Set fetch bit if fetch is the first operand.
        if (operands[0] == "fetch") {
            inst.imm |= EBPF_ATOMIC_OP_FETCH;
        }
        return inst;
    }

    bpf_encode_result_t
    _encode_atomic_xchg(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (mnemonic.ends_with("32")) {
            inst.opcode = EBPF_OP_ATOMIC32_STORE;
        } else {
            inst.opcode = EBPF_OP_ATOMIC_STORE;
        }
        auto [dst, offset] = _decode_register_and_offset(operands[1]);
        inst.dst = dst;
        inst.offset = offset;
        inst.src = _decode_register(operands[2]);
        // EPBF_ATOMIC_OP_XCHG always has the fetch bit set.
        inst.imm = EPBF_ATOMIC_OP_XCHG;
        return inst;
    }

    bpf_encode_result_t
    _encode_atomic_cmpxchg(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (mnemonic.ends_with("32")) {
            inst.opcode = EBPF_OP_ATOMIC32_STORE;
        } else {
            inst.opcode = EBPF_OP_ATOMIC_STORE;
        }
        auto [dst, offset] = _decode_register_and_offset(operands[1]);
        inst.dst = dst;
        inst.offset = offset;
        inst.src = _decode_register(operands[2]);
        // EBPF_ATOMIC_OP_CMPXCHG always has the fetch bit set.
        inst.imm = EBPF_ATOMIC_OP_CMPXCHG;
        return inst;
    }

    const std::unordered_map<std::string, std::tuple<bpf_encode_t, size_t>> _bpf_mnemonic_map{
        {"add", {&_bpf_assembler::_encode_alu, 2}},   {"add32", {&_bpf_assembler::_encode_alu, 2}},
        {"and", {&_bpf_assembler::_encode_alu, 2}},   {"and32", {&_bpf_assembler::_encode_alu, 2}},
        {"arsh", {&_bpf_assembler::_encode_alu, 2}},  {"arsh32", {&_bpf_assembler::_encode_alu, 2}},
        {"be16", {&_bpf_assembler::_encode_alu, 1}},  {"be32", {&_bpf_assembler::_encode_alu, 1}},
        {"be64", {&_bpf_assembler::_encode_alu, 1}},  {"call", {&_bpf_assembler::_encode_jmp, 2}},
        {"div", {&_bpf_assembler::_encode_alu, 2}},   {"div32", {&_bpf_assembler::_encode_alu, 2}},
        {"exit", {&_bpf_assembler::_encode_jmp, 0}},  {"ja", {&_bpf_assembler::_encode_jmp, 1}},
        {"ja32", {&_bpf_assembler::_encode_jmp, 1}},
        {"jeq", {&_bpf_assembler::_encode_jmp, 3}},   {"jeq32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jge", {&_bpf_assembler::_encode_jmp, 3}},   {"jge32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jgt", {&_bpf_assembler::_encode_jmp, 3}},   {"jgt32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jle", {&_bpf_assembler::_encode_jmp, 3}},   {"jle32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jlt", {&_bpf_assembler::_encode_jmp, 3}},   {"jlt32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jne", {&_bpf_assembler::_encode_jmp, 3}},   {"jne32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jset", {&_bpf_assembler::_encode_jmp, 3}},  {"jset32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jsge", {&_bpf_assembler::_encode_jmp, 3}},  {"jsge32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jsgt", {&_bpf_assembler::_encode_jmp, 3}},  {"jsgt32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jsle", {&_bpf_assembler::_encode_jmp, 3}},  {"jsle32", {&_bpf_assembler::_encode_jmp, 3}},
        {"jslt", {&_bpf_assembler::_encode_jmp, 3}},  {"jslt32", {&_bpf_assembler::_encode_jmp, 3}},
        {"lddw", {&_bpf_assembler::_encode_ld, 2}},   {"ldxb", {&_bpf_assembler::_encode_ldx, 2}},
        {"ldxdw", {&_bpf_assembler::_encode_ldx, 2}}, {"ldxh", {&_bpf_assembler::_encode_ldx, 2}},
        {"ldxw", {&_bpf_assembler::_encode_ldx, 2}},  {"le16", {&_bpf_assembler::_encode_alu, 1}},
        {"le32", {&_bpf_assembler::_encode_alu, 1}},  {"le64", {&_bpf_assembler::_encode_alu, 1}},
        {"lsh", {&_bpf_assembler::_encode_alu, 2}},   {"lsh32", {&_bpf_assembler::_encode_alu, 2}},
        {"mod", {&_bpf_assembler::_encode_alu, 2}},   {"mod32", {&_bpf_assembler::_encode_alu, 2}},
        {"mov", {&_bpf_assembler::_encode_alu, 2}},   {"mov32", {&_bpf_assembler::_encode_alu, 2}},
        {"movsx864", {&_bpf_assembler::_encode_alu, 2}}, {"movsx832", {&_bpf_assembler::_encode_alu, 2}},
        {"movsx1664", {&_bpf_assembler::_encode_alu, 2}}, {"movsx1632", {&_bpf_assembler::_encode_alu, 2}},
        {"movsx3264", {&_bpf_assembler::_encode_alu, 2}},
        {"mul", {&_bpf_assembler::_encode_alu, 2}},   {"mul32", {&_bpf_assembler::_encode_alu, 2}},
        {"neg", {&_bpf_assembler::_encode_alu, 1}},   {"neg32", {&_bpf_assembler::_encode_alu, 1}},
        {"or", {&_bpf_assembler::_encode_alu, 2}},    {"or32", {&_bpf_assembler::_encode_alu, 2}},
        {"rsh", {&_bpf_assembler::_encode_alu, 2}},   {"rsh32", {&_bpf_assembler::_encode_alu, 2}},
        {"sdiv", {&_bpf_assembler::_encode_alu, 2}},  {"sdiv32", {&_bpf_assembler::_encode_alu, 2}},
        {"smod", {&_bpf_assembler::_encode_alu, 2}},  {"smod32", {&_bpf_assembler::_encode_alu, 2}},
        {"stb", {&_bpf_assembler::_encode_st, 2}},    {"stdw", {&_bpf_assembler::_encode_st, 2}},
        {"sth", {&_bpf_assembler::_encode_st, 2}},    {"stw", {&_bpf_assembler::_encode_st, 2}},
        {"stxb", {&_bpf_assembler::_encode_stx, 2}},  {"stxdw", {&_bpf_assembler::_encode_stx, 2}},
        {"stxh", {&_bpf_assembler::_encode_stx, 2}},  {"stxw", {&_bpf_assembler::_encode_stx, 2}},
        {"sub", {&_bpf_assembler::_encode_alu, 2}},   {"sub32", {&_bpf_assembler::_encode_alu, 2}},
        {"swap16", {&_bpf_assembler::_encode_alu, 1}},{"swap32", {&_bpf_assembler::_encode_alu, 1}},
        {"swap64", {&_bpf_assembler::_encode_alu, 1}},{"xor", {&_bpf_assembler::_encode_alu, 2}},
        {"xor32", {&_bpf_assembler::_encode_alu, 2}},
    };

    const std::unordered_map<std::string, std::tuple<bpf_encode_t, size_t>> _bpf_encode_atomic_ops{
        {"add", {&_bpf_assembler::_encode_atomic_add, 3}},
        {"add32", {&_bpf_assembler::_encode_atomic_add, 3}},
        {"and", {&_bpf_assembler::_encode_atomic_and, 3}},
        {"and32", {&_bpf_assembler::_encode_atomic_and, 3}},
        {"or", {&_bpf_assembler::_encode_atomic_or, 3}},
        {"or32", {&_bpf_assembler::_encode_atomic_or, 3}},
        {"xor", {&_bpf_assembler::_encode_atomic_xor, 3}},
        {"xor32", {&_bpf_assembler::_encode_atomic_xor, 3}},
        {"xchg", {&_bpf_assembler::_encode_atomic_xchg, 3}},
        {"xchg32", {&_bpf_assembler::_encode_atomic_xchg, 3}},
        {"cmpxchg", {&_bpf_assembler::_encode_atomic_cmpxchg, 3}},
        {"cmpxchg32", {&_bpf_assembler::_encode_atomic_cmpxchg, 3}},
    };

  public:
    _bpf_assembler() = default;
    ~_bpf_assembler() = default;

    std::vector<ebpf_inst>
    assemble(std::istream& input)
    {
        size_t exit_count = 0;
        _jump_instructions.clear();
        _labels.clear();
        std::vector<ebpf_inst> output;
        std::string line;
        // Parse the input stream one line at a time.
        while (std::getline(input, line)) {
            std::istringstream line_stream(line);
            std::string mnemonic;
            std::string operand;
            std::vector<std::string> operands;
            // Check for empty lines.
            if (!std::getline(line_stream, mnemonic, ' ')) {
                continue;
            }
            // Split the line on ' '
            while (std::getline(line_stream, operand, ' ')) {
                if (operand.starts_with('#')) {
                    break;
                }
                if (operand.ends_with(',')) {
                    operand = operand.substr(0, operand.length() - 1);
                }
                operands.emplace_back(operand);
            }

            // Check for labels.
            if (mnemonic.ends_with(':')) {
                auto label =  mnemonic.substr(0, mnemonic.length() - 1);
                if (_labels.contains(label)) {
                    std::stringstream ss{};
                    ss << "Duplicate label (" + label + ") detected at line " << output.size() << " (previous declaration at line " << _labels[label] << ")";
                    throw std::runtime_error(ss.str());
                }
                _labels[label] = output.size();
                continue;
            }

            // Add a default exit label for the first exit statement.
            if (mnemonic == "exit" && exit_count == 0) {
                _labels[mnemonic] = output.size();
                exit_count++;
            }

            // Assume not a jump instruction.
            _jump_instructions.push_back({});

            bpf_encode_t encode = nullptr;
            size_t operand_count = 0;

            // If this is a call instruction and it doesn't specify a mode, add the default mode (helper).
            if (mnemonic == "call") {
                if (operands.size() == 1) {
                    operands.insert(operands.begin(), "helper");
                }
            }

            if (mnemonic == "lock") {
                // Find the handler for this atomic operation.
                if (operands.size() == 0) {
                    throw std::runtime_error("Invalid number of operands for lock");
                }

                // Format of interlocked operations is:
                // lock [fetch] <op> <dst>, <src>
                // where fetch is optional.

                // For simpler processing, insert a "no_fetch" operand if it is missing.
                if (operands.size() > 1 && operands[0] != "fetch") {
                    operands.insert(operands.begin(), "no_fetch");
                }

                // Swap fetch and op.
                std::swap(operands[0], operands[1]);

                // Format of interlocked operations is now:
                // lock <op> <fetch/no_fetch> <dst>, <src>

                auto iter = _bpf_encode_atomic_ops.find(operands[0]);
                if (iter != _bpf_encode_atomic_ops.end()) {
                    mnemonic = operands[0];
                    operands.erase(operands.begin());
                    std::tie(encode, operand_count) = iter->second;
                }
            } else {
                // Find the handler for this mnemonic.
                auto iter = _bpf_mnemonic_map.find(mnemonic);
                if (iter != _bpf_mnemonic_map.end()) {
                    std::tie(encode, operand_count) = iter->second;
                }
            }

            // Check if the mnemonic is valid.
            if (encode == nullptr) {
                throw std::runtime_error(std::string("Invalid mnemonic: ") + mnemonic);
            }

            // Check if the number of operands is valid.
            if (operands.size() != operand_count) {
                throw std::runtime_error(std::string("Invalid number of operands for mnemonic: ") + mnemonic);
            }

            // Invoke handler and store result.
            auto result = (this->*encode)(mnemonic, operands);
            if (std::holds_alternative<ebpf_inst>(result)) {
                output.emplace_back(std::get<ebpf_inst>(result));
            } else {
                // Instruction is 2 slots wide.
                _jump_instructions.push_back({});
                for (const auto& inst : std::get<std::array<ebpf_inst, 2>>(result)) {
                    output.emplace_back(inst);
                }
            }
        }

        // Fixup jump instructions.
        for (size_t i = 0; i < _jump_instructions.size(); i++) {
            if (!_jump_instructions[i].has_value()) {
                continue;
            }
            auto iter = _labels.find(_jump_instructions[i].value());
            if (iter == _labels.end()) {
                throw std::runtime_error(std::string("Invalid label: ") + _jump_instructions[i].value());
            }
            if (output[i].opcode == EBPF_OP_CALL || output[i].opcode == EBPF_OP_JA32) {
                output[i].imm = static_cast<uint32_t>(iter->second - i - 1);
            } else {
                output[i].offset = static_cast<uint16_t>(iter->second - i - 1);
            }
        }
        return output;
    }
} bpf_assembler_t;

std::vector<ebpf_inst>
bpf_assembler(std::istream& input)
{
    bpf_assembler_t assembler;
    return assembler.assemble(input);
}
