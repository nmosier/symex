#include "memstate.h"
#include "util.h"

namespace x86 {

#if 0
uint64_t MemState::Read::operator()(const cores::Core& core) const {
    const uint64_t addr = this->addr.get_numeral_uint64();
    switch (this->data.get_sort().bv_size() / 8) {
        case 1: return core.read<uint8_t>(addr);
        case 2: return core.read<uint16_t>(addr);
        case 4: return core.read<uint32_t>(addr);
        default: std::abort();
    }
}

z3::expr MemState::Read::operator()(const cores::Core& core, const ByteMap& write_mask) const {
    uint64_t addr = this->addr.get_numeral_uint64();
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
#endif


z3::expr MemState::get_init_mem(z3::context& ctx) {
    return ctx.constant("mem", ctx.array_sort(ctx.bv_sort(32), ctx.bv_sort(8)));
}

MemState::MemState(z3::context& ctx, cores::Core& core): core(core), mem(ctx) {
    mem = get_init_mem(ctx);
}

void MemState::initialize(const z3::expr& sym_addr, unsigned size, z3::solver& solver) {
    /* enumerate possibilities */
    std::vector<z3::expr> con_addrs;
    z3::enumerate(solver, sym_addr, std::back_inserter(con_addrs));

    /* initialize all writes */
    for (const z3::expr& con_addr : con_addrs) {
        for (unsigned i = 0; i < size; ++i) {
            const uint64_t int_addr = con_addr.get_numeral_uint64() + i;
            if (init.insert(int_addr).second) {
                /* initialize address */
                const uint8_t byte = core.read<uint8_t>(int_addr);
                mem = z3::store(mem, ctx().bv_val(int_addr, 32), ctx().bv_val(byte, 8));
            }
        }
    }
}

z3::expr MemState::read(const z3::expr &sym_addr, unsigned size, z3::solver& solver) {
    initialize(sym_addr, size, solver);
    
    /* perform read */
    std::vector<z3::expr> little;
    for (unsigned i = 0; i < size; ++i) {
        const z3::expr sym_byte = mem[sym_addr + ctx().bv_val(i, 32)];
        little.push_back(sym_byte);
    }
    const z3::expr res = z3::concat(little.rbegin(), little.rend());
    
    return res;
}

void MemState::write(const z3::expr& sym_addr, const z3::expr& value, z3::solver& solver) {
    const unsigned bits = value.get_sort().bv_size();
    const unsigned size = bits / 8;
    initialize(sym_addr, size, solver);
    
    /* perform write */
    for (unsigned i = 0; i < size; ++i) {
        mem = z3::store(mem, sym_addr + ctx().bv_val(i, 32), value.extract((i + 1) * 8 - 1, i * 8));
    }
}

}
