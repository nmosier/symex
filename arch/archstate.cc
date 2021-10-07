#include "archstate.h"
#include "util.h"

namespace x86 {

std::ostream& operator<<(std::ostream& os, const ArchState& arch) {
#define ENT(name, ...) os << #name << ": " << arch.name.simplify() << "\n";
    X_x86_REGS(ENT, ENT);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
    return os;
}

#define ENT_(name, ...) name(ctx)
#define ENT(name, ...) ENT_(name),
ArchState::ArchState(z3::context& ctx):
X_x86_REGS(ENT, ENT_), X_x86_FLAGS(ENT, ENT_), mem(ctx) {
    for (std::size_t i = 0; i < nxmms; ++i) {
        xmms.emplace_back(ctx);
    }
    zero();
}
#undef ENT_
#undef ENT

void ArchState::symbolic() {
#define ENT32(name, ...) name = ctx().bv_const(#name, 32);
#define ENT1(name, ...) name = ctx().bv_const(#name, 1);
    X_x86_REGS(ENT32, ENT32);
    X_x86_FLAGS(ENT1, ENT1);
#undef ENT32
#undef ENT1
    for (std::size_t i = 0; i < nxmms; ++i) {
        auto& xmm = xmms.at(i);
        std::stringstream ss;
        ss << "xmm" << i;
        xmm = ctx().bv_const(ss.str().c_str(), xmm_bits);
    }
    mem.mem = ctx().constant("tmpmem", ctx().array_sort(ctx().bv_sort(32), ctx().bv_sort(8)));
}

void ArchState::create(unsigned id, z3::solver& solver) {
#if 0
    const auto f = [&] (z3::expr& val, unsigned bits, const std::string& s_) {
        if (!val.is_const()) {
            const std::string s = s_ + "_" + std::to_string(id);
            const z3::expr newval = val.ctx().bv_const(s.c_str(), bits);
            solver.add(val == newval);
            val = newval;
        }
    };
#else
    const auto f = [] (z3::expr& val, unsigned bits, const std::string& s_) { return val; };
#endif
    
#define ENT(name) f(name, 32, #name);
    X_x86_REGS(ENT, ENT);
#undef ENT
#define ENT(name, ...) f(name, 1, #name);
    X_x86_FLAGS(ENT, ENT);
#undef ENT1
#undef ENT
    for (std::size_t i = 0; i < nxmms; ++i) {
        f(xmms[i], 128, util::format("xmm_%d", i));
    }
}

// TODO: this is useless, currently
z3::expr ArchState::operator==(const ArchState& other) const {
    const z3::expr xmm_cmp = xmms == other.xmms;
#define ENT_(name, ...) name == other.name
#define ENT(name, ...) ENT_(name) &&
    return X_x86_REGS(ENT, ENT_) && X_x86_FLAGS(ENT, ENT_) && xmm_cmp;
#undef ENT
#undef ENT_
}

void ArchState::transform_expr(std::function<z3::expr (const z3::expr&)> f) {
#define ENT(name, ...) name = f(name);
    X_x86_REGS(ENT, ENT);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
    for (z3::expr& xmm : xmms) {
        xmm = f(xmm);
    }
    
    mem.mem = f(mem.mem);
}

}
