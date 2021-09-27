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
    
    void simplify() {
#define ENT(name, ...) name = name.simplify();
        X_x86_REGS(ENT, ENT);
        X_x86_FLAGS(ENT, ENT);
#undef ENT
        for (z3::expr& xmm : xmms) {
            xmm = xmm.simplify();
        }
    }
    
    z3::expr operator==(const ArchState& other) const;
};

std::ostream& operator<<(std::ostream& os, const ArchState& arch);

#if 0
struct ArchState::Sort {
    z3::sort reg;
    z3::func_decl cons;
    z3::sort sort;
    z3::func_decl_vector projs;
    MemState::Sort mem;
    
    enum class Fields {
        XM_LIST(X_x86_REGS),
        XM_LIST(X_x86_FLAGS)
    };
    
    Sort(z3::context& ctx);
    
    ArchState unpack(const z3::expr& e) const;
    z3::expr pack(ArchState& arch) const;
};
#endif

}
