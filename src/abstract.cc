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
    
    const z3::expr len = ctx.bv_const(util::to_string("strlen", id++).c_str(), 32);
    const z3::expr idx = ctx.bv_const("idx", 32);
    const z3::expr is_zero = mem[addr + len] == 0;
    const z3::expr is_nonzero = z3::forall(idx, z3::implies(idx >= 0 && idx < len, mem[addr + idx] != 0));
    const z3::expr pred = (len >= 0 && is_zero && is_nonzero);
    
    z3::expr_vector assignments {ctx};
    if (z3::unique_assignment(solver, pred, z3::make_expr_vector(ctx, len), assignments)) {
        /* found unique concrete assignment */
        return assignments[0];
    } else {
        solver.add(pred);
        return len;
    }
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

z3::expr tolower(const z3::expr& c) {
    return z3::ite('A' <= c && c <= 'Z', c - 'A', c);
}

/// returns strncasecmp
z3::expr strncasecmp(const x86::ArchState& arch, const z3::expr& s1, const z3::expr& s2, const z3::expr& n, z3::solver& solver) {
    static unsigned id = 0;
    
    z3::context& ctx = arch.ctx();
    const z3::expr& mem = arch.mem.mem;
    
    const uint64_t con_s1 = s1.get_numeral_uint64();
    const uint64_t con_s2 = s2.get_numeral_uint64();
    const uint64_t con_n = n.get_numeral_uint64();
    
    z3::expr acc = ctx.bv_val(0, 32);
    uint64_t i = con_n;
    while (i-- > 0) {
        const z3::expr sym_i = ctx.bv_val(i, 32);
        const z3::expr diff = mem[s1 + sym_i] - mem[s2 + sym_i];
        acc = z3::ite(diff == 0, acc, diff);
    }
    
    return acc;
}



namespace detail {

/* Check if the next N characters are concerete */
template <class OutputIt>
bool check_string_concrete_n(const x86::ArchState& arch, const z3::expr& addr0, z3::solver& solver, const cores::Core& core, const ByteMap& write_mask, OutputIt out, unsigned n) {
    z3::context& ctx = arch.ctx();

    z3::expr_vector sym_chars {ctx};
    for (unsigned i = 0; i < n; ++i) {
        const z3::expr sym_i = ctx.bv_val(i, 32);
        const z3::expr addr = addr0 + sym_i;
        const Read read {addr, arch.mem.mem[addr]};
        z3::expr symc = read(core, write_mask);
        sym_chars.push_back(symc);
    }
    
    z3::expr_vector con_chars {ctx};
    if (z3::unique_assignment(solver, ctx.bool_val(true), sym_chars, con_chars)) {
        util::copy(con_chars, out);
        return true;
    } else {
        return false;
    }
}

}


/* Check if string is concrete. If so, return string. */
template <class OutputIt>
bool check_string_concrete(const x86::ArchState& arch, const z3::expr& addr, z3::solver& solver, const cores::Core& core, const ByteMap& write_mask, OutputIt out) {
    z3::context& ctx = arch.ctx();
    while (true) {
        const Read read {addr, arch.mem.mem[addr]};
        z3::expr sym_c = read(core, write_mask);
        /* try simplifying */
        if (!sym_c.is_numeral()) {
            sym_c = sym_c.simplify();
        }
        /* check uniqueness */
        z3::expr con_c {ctx};
        if (sym_c.is_numeral()) {
            con_c = sym_c;
        } else {
            if (!z3::unique_assignment(solver, ctx.bool_val(true), sym_c, con_c)) {
                return false;
            }
        }
        
        *out++ = con_c.get_numeral_uint64();
    }
}


}

void sym_strncasecmp(x86::ArchState& arch, z3::solver& solver, ReadOut read_out, WriteOut write_out, ByteMap& write_mask, const cores::Core& core) {
    
    std::cerr << "TRANSFER " << __FUNCTION__ << "\n";
    
    z3::context& ctx = arch.ctx();
    
    z3::expr s1 {ctx};
    z3::expr s2 {ctx};
    z3::expr n {ctx};
    args(arch, s1, s2, n);
    
    z3::expr_vector variables {ctx};
    variables.push_back(n);
    variables.push_back(s1);
    variables.push_back(s2);
    z3::expr_vector assignments {ctx};
    if (!z3::unique_assignment(solver, ctx.bool_val(true), variables, assignments)) {
        std::cerr << "non-unique assignment\n";
        std::abort();
    }
    const z3::expr con_n = assignments[0];
    const z3::expr con_s1 = assignments[1];
    const z3::expr con_s2 = assignments[2];
    
    std::cerr << "strncasecmp(" << con_s1 << ", " << con_s2 << ", " << con_n << ")\n";
    
    z3::expr& mem = arch.mem.mem;
    
    /* check whether all previous bytes are zero */
    z3::expr_vector s1_nonzero {ctx};
    z3::expr_vector s2_nonzero {ctx};
    z3::expr_vector diff {ctx};
    for (uint32_t i = 0; i < con_n.get_numeral_uint64(); ++i) {
        std::cerr << i << "\n";
        const z3::expr sym_i = ctx.bv_val(i, 32);
        const z3::expr addr_s1 = (con_s1 + sym_i).simplify();
        const z3::expr addr_s2 = (con_s2 + sym_i).simplify();
        Read s1_read {addr_s1, mem[addr_s1]};
        Read s2_read {addr_s2, mem[addr_s2]};
        const z3::expr s1_byte = s1_read(core, write_mask);
        const z3::expr s2_byte = s2_read(core, write_mask);
        s1_nonzero.push_back(s1_byte != 0);
        s2_nonzero.push_back(s2_byte != 0);
        diff.push_back(s1_byte - s2_byte);
        
        z3::expr_vector assumptions {ctx};
        assumptions.push_back(z3::mk_and(s1_nonzero));
        assumptions.push_back(z3::mk_and(s2_nonzero));
        if (solver.check(assumptions) == z3::unsat) {
            break;
        }
    }
    
    unsigned i = diff.size();
    z3::expr acc = ctx.bv_val(0, 8);
    while (i-- > 0) {
        acc = z3::ite(diff[i] == 0, acc, diff[i]);
    }
    
    ret(arch, z3::sext(acc, 32 - 8));
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
