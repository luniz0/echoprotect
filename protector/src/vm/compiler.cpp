#include "protector/vm/compiler.hpp"
#include "protector/ir/types.hpp"

namespace prt::vm {

static void EmitNoise(std::vector<uint8_t>& bc) {
    bc.push_back(0x11); // OP_PAD
    bc.push_back(0x55); // OP_ACC_MIX
}

static void EmitConstValue(int64_t value, std::vector<uint8_t>& bc) {
    uint8_t lo = static_cast<uint8_t>(value & 0xFF);
    bc.push_back(0xA3); // OP_XOR_IMM
    bc.push_back(lo);
}

std::vector<uint8_t> CompileFunctionToVmBytecode(const prt::ir::Function& fn) {
    std::vector<uint8_t> bc;
    bc.reserve(fn.blocks.size() * 8 + 16);

    // Encode basic control-flow and constants into the VM dispatch.
    for (const auto& bb : fn.blocks) {
        EmitNoise(bc);
        for (const auto& ins : bb.insts) {
            switch (ins.opcode) {
            case prt::ir::Opcode::Const:
                EmitConstValue(ins.const_imm, bc);
                break;
            case prt::ir::Opcode::Copy:
                bc.push_back(0x66); // OP_SCRAMBLE as a no-op slot
                break;
            case prt::ir::Opcode::ICmp:
                bc.push_back(0xB5); // OP_CMP_IMM32
                bc.push_back(static_cast<uint8_t>(ins.const_imm & 0xFF));
                bc.push_back(static_cast<uint8_t>((ins.const_imm >> 8) & 0xFF));
                bc.push_back(static_cast<uint8_t>((ins.const_imm >> 16) & 0xFF));
                bc.push_back(static_cast<uint8_t>((ins.const_imm >> 24) & 0xFF));
                bc.push_back(0xB3); // OP_SET_FLAG
                break;
            case prt::ir::Opcode::Branch:
                bc.push_back(0x11); // OP_PAD for branch placeholders
                break;
            default:
                bc.push_back(0x11); // OP_PAD
                break;
            }
        }
    }

    bc.push_back(0x77); // OP_EMIT_WIN
    return bc;
}

} // namespace prt::vm
