#include "protector/runner.hpp"
#include "protector/pe/image.hpp"
#include "protector/disasm/decoder.hpp"
#include "protector/cfg/builder.hpp"
#include "protector/ir/lifter.hpp"
#include "protector/analysis/vsa.hpp"
#include "protector/vm/compiler.hpp"
#include <windows.h>
#include <array>
#include <algorithm>
#include <filesystem>
#include <vector>

namespace prt::runner {

namespace {

const prt::pe::Section* FindTextSection(const prt::pe::Image& img) {
    for (const auto& section : img.sections) {
        if (section.name == ".text") return &section;
    }
    return nullptr;
}

} // namespace

bool InitializeProtectionPipeline() {
    wchar_t module_path[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, module_path, ARRAYSIZE(module_path))) {
        return false;
    }

    prt::pe::Image img;
    if (!img.LoadFromFile(module_path).ok) {
        return false;
    }

    const prt::pe::Section* text_section = FindTextSection(img);
    if (!text_section) {
        return false;
    }

    const uint32_t entry_rva = img.EntryPointRva();
    const uint8_t* entry_code = img.RvaToPtr(entry_rva);
    if (!entry_code) {
        return false;
    }

    const size_t entry_offset = static_cast<size_t>(entry_rva - text_section->virtual_address);
    if (entry_offset >= text_section->raw_size) {
        return false;
    }

    const size_t code_len = text_section->raw_size - entry_offset;
    prt::disasm::ZydisDecoder decoder;
    prt::cfg::CFGBuilder cfg_builder(decoder);
    prt::cfg::CfgGraph cfg = cfg_builder.Build(entry_rva, entry_code, code_len);
    if (cfg.blocks.empty()) {
        return false;
    }

    prt::analysis::VsaEngine vsa;
    vsa.RunOnCfg(cfg, 0);

    prt::ir::Lifter lifter;
    prt::ir::Function fn = lifter.Lift(cfg, 0);
    if (fn.blocks.empty()) {
        return false;
    }

    std::vector<uint8_t> vm_bytecode = prt::vm::CompileFunctionToVmBytecode(fn);
    const std::vector<uint8_t> stub_bytes;
    uint32_t section_rva = 0;

    if (!prt::pe::PeBuilder::InjectVmSection(img, stub_bytes, vm_bytecode, entry_rva, &section_rva).ok) {
        return false;
    }

    const std::filesystem::path current_exe(module_path);
    const std::filesystem::path protected_path = current_exe.replace_extension(L".protected.exe");
    if (!img.SaveToFile(protected_path.native()).ok) {
        return false;
    }

    return !vm_bytecode.empty();
}

} // namespace prt::runner
