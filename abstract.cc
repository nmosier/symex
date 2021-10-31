#include "abstract.h"

namespace transfer {

namespace {

namespace detail {

template <int I>
void args_impl(const x86::ArchState& arch) {}

template <int I, typename... Ts>
void args_impl(const x86::ArchState& arch, z3::expr& arg, Ts&... ts) {
    arg = arch.mem.read(arch.esp + (I + 1) * 4, 4, util::null_output_iterator());
    args_impl<I+1>(arch, ts...);
}

}

template <typename... Ts>
void args(const x86::ArchState& arch, Ts&... ts) {
    detail::args_impl<0>(arch, ts...);
}

void ret(x86::ArchState& arch, const z3::expr& rv) {
    arch.eip = arch.mem.read(arch.esp, 4, util::null_output_iterator());
    arch.esp = arch.esp + 4;
}

/// returns length
z3::expr strlen(const x86::ArchState& arch, const z3::expr& addr, z3::solver& solver) {
    static unsigned id = 0;
    z3::context& ctx = arch.ctx();
    const z3::expr& mem = arch.mem.mem;
    
    // see if we can 
    
    
    
    const z3::expr len = ctx.bv_const(util::to_string("strlen", id++).c_str(), 32);
    const z3::expr idx = ctx.bv_const("idx", 32);
    const z3::expr is_zero = mem[addr + len] == 0;
    const z3::expr is_nonzero = z3::forall(idx, z3::implies(idx >= 0 && idx < len, mem[addr + idx] != 0));
    solver.add(len >= 0 && is_zero && is_nonzero);
    
    return len;
}

/// returns length
z3::expr strnlen(const x86::ArchState& arch, const z3::expr& addr, const z3::expr& maxlen, z3::solver& solver) {
    return z3::min(strlen(arch, addr, solver), maxlen);
}

/// returns new memory array
z3::expr memcpy(const x86::ArchState& arch, const z3::expr& dst, const z3::expr& src, const z3::expr& len) {
    z3::context& ctx = arch.ctx();
    const z3::expr& mem = arch.mem.mem;
    
    z3::expr addr = ctx.bv_const("addr", 32);
    const z3::expr adjusted_addr = z3::ite(addr >= dst && addr < dst + len, addr - dst + src, addr);
    return z3::lambda(addr, mem[adjusted_addr]);
}

}

void sym_nop(x86::ArchState& arch, z3::solver& solver) {
    ret(arch, arch.ctx().bv_val(0, 32));
}

void sym_memcpy(x86::ArchState& arch, z3::solver& solver) {
    z3::context& ctx = arch.ctx();
    
    z3::expr dst {ctx};
    z3::expr src {ctx};
    z3::expr len {ctx};
    args(arch, dst, src, len);
    
    arch.mem.mem = memcpy(arch, dst, src, len);
    
    /* return address */
    ret(arch, dst);
}


void sym_strncat(x86::ArchState& arch, z3::solver& solver) {
    z3::context& ctx = arch.ctx();
    z3::expr mem = arch.mem.mem;
    
    z3::expr dst {ctx}, src {ctx}, len {ctx};
    args(arch, dst, src, len);
    
    /* get length of dst string */
    const z3::expr dst_len = strlen(arch, dst, solver);
    
    /* memcpy */
    mem = memcpy(arch, dst + dst_len, src, len);
    mem = z3::store(mem, dst + dst_len + len, ctx.bv_val(0, 8));
    
    ret(arch, dst);
}

void sym_strnlen(x86::ArchState& arch, z3::solver& solver) {
    z3::context& ctx = arch.ctx();
    z3::expr mem = arch.mem.mem;
    
    z3::expr src {ctx};
    z3::expr maxlen {ctx};
    args(arch, src, maxlen);
    
    z3::expr res = strnlen(arch, src, maxlen, solver);
    
    ret(arch, res);
}

}
