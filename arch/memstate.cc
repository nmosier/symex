#include "memstate.h"
#include "util.h"

namespace x86 {

uint64_t MemState::Read::operator()(const cores::Core& core) const {
    const uint64_t addr = this->addr.as_uint64();
    switch (this->data.get_sort().bv_size() / 8) {
        case 1: return core.read<uint8_t>(addr);
        case 2: return core.read<uint16_t>(addr);
        case 4: return core.read<uint32_t>(addr);
        default: std::abort();
    }
}

z3::expr MemState::Read::operator()(const cores::Core& core, const ByteMap& write_mask) const {
    uint64_t addr = this->addr.as_uint64();
    z3::expr data = this->data;
    std::vector<z3::expr> res;
    for (unsigned i = 0; i < size(); ++i) {
        z3::expr byte {ctx()};
        if (write_mask.find(addr + i) == write_mask.end()) {
            byte = ctx().bv_val(core.read<uint8_t>(addr + i), 8);
        } else {
            byte = data.extract((i + 1) * 8 - 1, i * 8);
        }
        res.push_back(byte);
    }
    return z3::concat(res.rbegin(), res.rend());
}

MemState::MemState(z3::context& ctx): ctx_(&ctx), mem(ctx) {
    mem = get_init_mem(ctx);
}

}
