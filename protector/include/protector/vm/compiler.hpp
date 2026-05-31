#pragma once

#include "protector/ir/types.hpp"
#include <vector>
#include <cstdint>

namespace prt::vm {

std::vector<uint8_t> CompileFunctionToVmBytecode(const prt::ir::Function& fn);

} // namespace prt::vm
