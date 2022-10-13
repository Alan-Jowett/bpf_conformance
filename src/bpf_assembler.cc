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
        {"r0", 0},
        {"r1", 1},
        {"r2", 2},
        {"r3", 3},
        {"r4", 4},
        {"r5", 5},
        {"r6", 6},
        {"r7", 7},
        {"r8", 8},
        {"r9", 9},
        {"r10", 10},
        // Add fake registers to support negative tests.
        {"r11", 11},
        {"r12", 12},
        {"r13", 13},
        {"r14", 14},
        {"r15", 15},
    };

    const std::unordered_map<std::string, int> _bpf_encode_alu_ops{
        {"add", 0x0},
        {"sub", 0x1},
        {"mul", 0x2},
        {"div", 0x3},
        {"or", 0x4},
        {"and", 0x5},
        {"lsh", 0x6},
        {"rsh", 0x7},
        {"neg", 0x8},
        {"mod", 0x9},
        {"xor", 0xa},
        {"mov", 0xb},
        {"arsh", 0xc},
        {"le", 0xd},
        {"be", 0xd},
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

    // Labels discoverd while parsing the assembly code.
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
            return std::stoul(str);
        } else {
            return std::stoul(str, nullptr, 16);
        }
    }

    uint16_t
    _decode_offset(const std::string& str)
    {
        if (str.find("0x") == std::string::npos) {
            return static_cast<uint16_t>(std::stoul(str));
        } else {
            return static_cast<uint16_t>(std::stoul(str, nullptr, 16));
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
            throw std::runtime_error(std::string("Invalid operand: ") + operand);
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
    _encode_ld(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        std::array<ebpf_inst, 2> inst{};
        if (mnemonic != "lddw") {
            throw std::runtime_error(std::string("Invalid mnemonic: ") + mnemonic);
        }
        if (operands.size() != 2) {
            throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
        }
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
        if (operands.size() != 2) {
            throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
        }
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
        } else {
            throw std::runtime_error(std::string("Invalid mnemonic: ") + mnemonic);
        }

        return inst;
    }

    bpf_encode_result_t
    _encode_st(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (operands.size() != 2) {
            throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
        }
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
        } else {
            throw std::runtime_error(std::string("Invalid mnemonic: ") + mnemonic);
        }
        inst.imm = _decode_imm32(operands[1]);
        return inst;
    }

    bpf_encode_result_t
    _encode_stx(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        if (operands.size() != 2) {
            throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
        }
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
        } else {
            throw std::runtime_error(std::string("Invalid mnemonic: ") + mnemonic);
        }

        return inst;
    }

    bpf_encode_result_t
    _encode_alu(const std::string& mnemonic, const std::vector<std::string>& operands)
    {
        ebpf_inst inst{};
        std::string alu_op;
        if (mnemonic.starts_with("be")) {
            if (operands.size() != 1) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }
            inst.opcode = EBPF_OP_BE;
            inst.dst = _decode_register(operands[0]);
            inst.imm = _decode_imm32(mnemonic.substr(2));
            return inst;
        } else if (mnemonic.starts_with("le")) {
            if (operands.size() != 1) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }
            inst.opcode = EBPF_OP_LE;
            inst.dst = _decode_register(operands[0]);
            inst.imm = _decode_imm32(mnemonic.substr(2));
            return inst;
        }

        if (mnemonic.starts_with("neg")) {
            if (operands.size() != 1) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }
        } else {
            if (operands.size() != 2) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }
        }

        if (mnemonic.ends_with("32")) {
            inst.opcode |= EBPF_CLS_ALU;
            alu_op = mnemonic.substr(0, mnemonic.size() - 2);
        } else {
            inst.opcode |= EBPF_CLS_ALU64;
            alu_op = mnemonic;
        }
        auto iter = _bpf_encode_alu_ops.find(alu_op);
        if (iter == _bpf_encode_alu_ops.end()) {
            throw std::runtime_error(std::string("Invalid mnemonic: ") + mnemonic);
        }
        inst.opcode |= iter->second << 4;

        inst.dst = _decode_register(operands[0]);

        if (operands.size() == 2) {
            if (operands[1].starts_with('r')) {
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
        inst.opcode |= EBPF_CLS_JMP;
        if (mnemonic == "ja") {
            if (operands.size() != 1) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }

            inst.offset = _decode_jump_target(operands[0]);
        } else if (mnemonic == "exit") {
            if (operands.size() != 0) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }
            inst.opcode = EBPF_OP_EXIT;
        } else if (mnemonic == "call") {
            if (operands.size() != 1) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }
            inst.opcode = EBPF_OP_CALL;
            inst.imm = _decode_imm32(operands[0]);
        } else {
            if (operands.size() != 3) {
                throw std::runtime_error(std::string("Wrong operand count: ") + mnemonic);
            }
            mnemonic.ends_with("32") ? inst.opcode = EBPF_CLS_JMP32 : inst.opcode |= EBPF_CLS_JMP;
            auto iter =
                _bpf_encode_jmp_ops.find(mnemonic.ends_with("32") ? mnemonic.substr(0, mnemonic.size() - 2) : mnemonic);
            inst.opcode |= iter->second << 4;
            inst.dst = _decode_register(operands[0]);
            if (operands[1].starts_with('r')) {
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

    // const std::function<bpf_encode_result_t(const std::string&, const std::vector<std::string>&)> some =
    // std::mem_fn(&_bpf_assembler::_encode_alu);

    const std::unordered_map<std::string, bpf_encode_t> _bpf_mnemonic_map{
        {"add", &_bpf_assembler::_encode_alu},   {"add32", &_bpf_assembler::_encode_alu},
        {"and", &_bpf_assembler::_encode_alu},   {"and32", &_bpf_assembler::_encode_alu},
        {"arsh", &_bpf_assembler::_encode_alu},  {"arsh32", &_bpf_assembler::_encode_alu},
        {"be16", &_bpf_assembler::_encode_alu},  {"be32", &_bpf_assembler::_encode_alu},
        {"be64", &_bpf_assembler::_encode_alu},  {"call", &_bpf_assembler::_encode_jmp},
        {"div", &_bpf_assembler::_encode_alu},   {"div32", &_bpf_assembler::_encode_alu},
        {"exit", &_bpf_assembler::_encode_jmp},  {"ja", &_bpf_assembler::_encode_jmp},
        {"jeq", &_bpf_assembler::_encode_jmp},   {"jeq32", &_bpf_assembler::_encode_jmp},
        {"jge", &_bpf_assembler::_encode_jmp},   {"jge32", &_bpf_assembler::_encode_jmp},
        {"jgt", &_bpf_assembler::_encode_jmp},   {"jgt32", &_bpf_assembler::_encode_jmp},
        {"jle", &_bpf_assembler::_encode_jmp},   {"jle32", &_bpf_assembler::_encode_jmp},
        {"jlt", &_bpf_assembler::_encode_jmp},   {"jlt32", &_bpf_assembler::_encode_jmp},
        {"jne", &_bpf_assembler::_encode_jmp},   {"jne32", &_bpf_assembler::_encode_jmp},
        {"jset", &_bpf_assembler::_encode_jmp},  {"jset32", &_bpf_assembler::_encode_jmp},
        {"jsge", &_bpf_assembler::_encode_jmp},  {"jsge32", &_bpf_assembler::_encode_jmp},
        {"jsgt", &_bpf_assembler::_encode_jmp},  {"jsgt32", &_bpf_assembler::_encode_jmp},
        {"jsle", &_bpf_assembler::_encode_jmp},  {"jsle32", &_bpf_assembler::_encode_jmp},
        {"jslt", &_bpf_assembler::_encode_jmp},  {"jslt32", &_bpf_assembler::_encode_jmp},
        {"lddw", &_bpf_assembler::_encode_ld},   {"ldxb", &_bpf_assembler::_encode_ldx},
        {"ldxdw", &_bpf_assembler::_encode_ldx}, {"ldxh", &_bpf_assembler::_encode_ldx},
        {"ldxw", &_bpf_assembler::_encode_ldx},  {"le16", &_bpf_assembler::_encode_alu},
        {"le32", &_bpf_assembler::_encode_alu},  {"le64", &_bpf_assembler::_encode_alu},
        {"lsh", &_bpf_assembler::_encode_alu},   {"lsh32", &_bpf_assembler::_encode_alu},
        {"mod", &_bpf_assembler::_encode_alu},   {"mod32", &_bpf_assembler::_encode_alu},
        {"mov", &_bpf_assembler::_encode_alu},   {"mov32", &_bpf_assembler::_encode_alu},
        {"mul", &_bpf_assembler::_encode_alu},   {"mul32", &_bpf_assembler::_encode_alu},
        {"neg", &_bpf_assembler::_encode_alu},   {"neg32", &_bpf_assembler::_encode_alu},
        {"or", &_bpf_assembler::_encode_alu},    {"or32", &_bpf_assembler::_encode_alu},
        {"rsh", &_bpf_assembler::_encode_alu},   {"rsh32", &_bpf_assembler::_encode_alu},
        {"stb", &_bpf_assembler::_encode_st},    {"stdw", &_bpf_assembler::_encode_st},
        {"sth", &_bpf_assembler::_encode_st},    {"stw", &_bpf_assembler::_encode_st},
        {"stxb", &_bpf_assembler::_encode_stx},  {"stxdw", &_bpf_assembler::_encode_stx},
        {"stxh", &_bpf_assembler::_encode_stx},  {"stxw", &_bpf_assembler::_encode_stx},
        {"sub", &_bpf_assembler::_encode_alu},   {"sub32", &_bpf_assembler::_encode_alu},
        {"xor", &_bpf_assembler::_encode_alu},   {"xor32", &_bpf_assembler::_encode_alu},

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
                _labels[mnemonic.substr(0, mnemonic.length() - 1)] = output.size();
                continue;
            }

            // Add a default exit label for the first exit statement.
            if (mnemonic == "exit" && exit_count == 0) {
                _labels[mnemonic] = output.size();
                exit_count++;
            }

            // Assume not a jump instruction.
            _jump_instructions.push_back({});

            // Find the handler for this mnemonic.
            auto iter = _bpf_mnemonic_map.find(mnemonic);
            if (iter == _bpf_mnemonic_map.end()) {
                throw std::runtime_error(std::string("Invalid mnemonic: ") + mnemonic);
            }
            // Invoke handler and store result.
            auto result = (this->*iter->second)(mnemonic, operands);
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
            output[i].offset = static_cast<uint16_t>(iter->second - i - 1);
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
