#pragma once

#include "memstate.h"

namespace x86 {

#define X_x86_REGS(XB, XE)            \
XB(eax)                    \
XB(ebx)                    \
XB(ecx)                    \
XB(edx)                    \
XB(edi)                    \
XB(esi)                    \
XB(ebp)                    \
XB(esp)                    \
XE(eip)


#define X_x86_FLAGS(XB, XE)            \
XB(cf, 0)                    \
XB(zf, 6)                    \
XB(sf, 7) \
XE(of, 11)

#define X_x86_MEMS(XB, XE)            \
XB(mem1)                        \
XB(mem2)                        \
XB(mem4)

struct ArchState {
#define ENT_(name, ...) z3::expr name
#define ENT(name, ...) ENT_(name);
    X_x86_REGS(ENT, ENT_);
    X_x86_FLAGS(ENT, ENT_);
#undef ENT_
#undef ENT
    static constexpr std::size_t nxmms = 8;
    static constexpr unsigned xmm_bits = 128;
    std::vector<z3::expr> xmms;
    
    MemState mem;
    
    ArchState(z3::context& ctx);
    
    void create(unsigned id, z3::solver& solver);
    
    z3::context& ctx() const { return eax.ctx(); }
    
    void zero() {
#define ENT_(name) name = ctx().bv_val(0, 32)
#define ENT(name) ENT_(name);
        X_x86_REGS(ENT, ENT_);
#undef ENT_
#undef ENT
#define ENT_(name, ...) name = ctx().bv_val(0, 1)
#define ENT(name, ...) ENT_(name);
        X_x86_FLAGS(ENT, ENT_);
#undef ENT_
#undef ENT
        for (z3::expr& xmm : xmms) {
            xmm = ctx().bv_val(0, xmm_bits);
        }
    }
    
    void transform_expr(std::function<z3::expr (const z3::expr&)> f);
    
    void simplify() {
        transform_expr([] (const z3::expr& e) -> z3::expr { return e.simplify(); });
    }
    
    void substitute(const z3::expr_vector& src, const z3::expr_vector& dst) {
        transform_expr([&src, &dst] (z3::expr e) -> z3::expr {
            return e.substitute(src, dst);
        });
    }
    
    void symbolic();
    
    static z3::expr substitute(z3::expr& e, const ArchState& src, const ArchState& dst);
    
    z3::expr operator==(const ArchState& other) const;
};

std::ostream& operator<<(std::ostream& os, const ArchState& arch);

}
