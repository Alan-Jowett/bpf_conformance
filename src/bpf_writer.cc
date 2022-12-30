// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <elfio/elfio.hpp>

#include "bpf_writer.h"

const std::string symbol_section_name = ".symtab";
// https://github.com/Alan-Jowett/bpf_conformance/issues/82
// Add support for the new BTF based .maps section.
const std::string maps_section_name = "maps";
const std::string relocation_prefix = ".rel";

void
bpf_writer_classic(
    std::ostream& output,
    const std::string& section_name,
    const std::string& function_name,
    const std::vector<ebpf_inst_t>& instructions,
    const std::vector<std::tuple<std::string, ebpf_map_definition_in_file_t>>& maps,
    const std::map<size_t, std::string>& map_relocations)
{
    ELFIO::elfio writer;
    writer.create(ELFIO::ELFCLASS64, ELFIO::ELFDATA2LSB);

    writer.set_type(ELFIO::ET_REL);
    writer.set_machine(ELFIO::EM_BPF);

    auto symbols_section = writer.sections.add(symbol_section_name);
    symbols_section->set_type(ELFIO::SHT_SYMTAB);
    symbols_section->set_flags(0);
    symbols_section->set_addr_align(4);
    symbols_section->set_info(1);
    symbols_section->set_entry_size(writer.get_default_entry_size(ELFIO::SHT_SYMTAB));
    symbols_section->set_link(writer.get_section_name_str_index());

    auto text_section = writer.sections.add(section_name);
    text_section->set_type(ELFIO::SHT_PROGBITS);
    text_section->set_flags(ELFIO::SHF_EXECINSTR | ELFIO::SHF_ALLOC);
    text_section->set_addr_align(4);
    text_section->append_data(
        reinterpret_cast<const char*>(instructions.data()),
        static_cast<ELFIO::Elf_Word>(instructions.size() * sizeof(ebpf_inst_t)));

    auto string_accessor = ELFIO::string_section_accessor(writer.sections[writer.get_section_name_str_index()]);
    auto symbol_accessor = ELFIO::symbol_section_accessor(writer, symbols_section);

    symbol_accessor.add_symbol(
        string_accessor,
        function_name.c_str(),
        text_section->get_address(),
        text_section->get_size(),
        ELFIO::STB_GLOBAL,
        ELFIO::STT_FUNC,
        0,
        text_section->get_index());

    if (maps.size() > 0) {
        auto relocation_section = writer.sections.add(relocation_prefix + section_name);
        auto maps_section = writer.sections.add(maps_section_name);
        maps_section->set_type(ELFIO::SHT_PROGBITS);
        maps_section->set_flags(ELFIO::SHF_WRITE | ELFIO::SHF_ALLOC);
        maps_section->set_addr_align(4);
        for (const auto& map : maps) {
            maps_section->append_data(
                reinterpret_cast<const char*>(&std::get<1>(map)), sizeof(ebpf_map_definition_in_file_t));
        }

        relocation_section->set_type(ELFIO::SHT_REL);
        relocation_section->set_flags(0);
        relocation_section->set_addr_align(8);
        relocation_section->set_info(text_section->get_index());
        relocation_section->set_link(symbols_section->get_index());
        relocation_section->set_entry_size(writer.get_default_entry_size(ELFIO::SHT_REL));

        auto relocation_accessor = ELFIO::relocation_section_accessor(writer, relocation_section);

        for (const auto& relocation : map_relocations) {
            auto map_entry = std::find_if(
                maps.begin(), maps.end(), [&](const auto& map) { return std::get<0>(map) == relocation.second; });
            if (map_entry == maps.end()) {
                throw std::runtime_error("Map not found");
            }
            size_t map_offset = std::distance(maps.begin(), map_entry) * sizeof(ebpf_map_definition_in_file_t);
            relocation_accessor.add_entry(
                string_accessor,
                relocation.second.c_str(),
                symbol_accessor,
                map_offset,
                sizeof(ebpf_map_definition_in_file_t),
                ELFIO::STB_GLOBAL << 4 | ELFIO::STT_OBJECT,
                0,
                maps_section->get_index(),
                relocation.first * sizeof(ebpf_inst_t),
                ELFIO::R_X86_64_64);
        }
    }

    writer.save(output);
}
