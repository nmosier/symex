#pragma once

#include "memstate.h"
#include "fpu.h"

namespace x86 {

#define X_x86_REGS(XB, XE)            \
XB(eax, 32)                    \
XB(ebx, 32)                    \
XB(ecx, 32)                    \
XB(edx, 32)                    \
XB(edi, 32)                    \
XB(esi, 32)                    \
XB(ebp, 32)                    \
XB(esp, 32)                    \
XE(eip, 32)

#define X_x86_FLAGS(XB, XE)            \
XB(cf, 1, 0)                    \
XB(zf, 1, 6)                    \
XB(sf, 1, 7) \
XB(of, 1, 11) \
XE(pf, 1, 4)

#define X_x86_XMMS(XB, XE) \
XB(xmm0, 128) \
XB(xmm1, 128) \
XB(xmm2, 128) \
XB(xmm3, 128) \
XB(xmm4, 128) \
XB(xmm5, 128) \
XB(xmm6, 128) \
XE(xmm7, 128)

#define X_x86_ALL(XB, XE) \
X_x86_REGS(XB, XB) \
X_x86_FLAGS(XB, XB) \
X_x86_XMMS(XB, XE)

struct ArchState {
#define ENT(name, ...) z3::expr name;
#define ENT_(...) ENT(__VA_ARGS__);
    X_x86_ALL(ENT, ENT_);
#undef ENT
#undef ENT_
    static constexpr std::size_t nxmms = 8;
    static constexpr unsigned xmm_bits = 128;
    
    MemState mem;
    FPUState fpu;
    
    ArchState(z3::context& ctx, cores::Core& core);
    
    void create(unsigned id, z3::solver& solver);
    
    z3::context& ctx() const { return eax.ctx(); }
    
    void zero() {
#define ENT(name, bits, ...) name = ctx().bv_val(0, bits);
        X_x86_ALL(ENT, ENT);
#undef ENT
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
    
    enum RegClass {
        REG  = 1 << 0,
        FLAG = 1 << 1,
        XMM  = 1 << 2,
        ALL  = REG | FLAG | XMM
    };
    
    static void for_each(int kind, std::function<void (z3::expr ArchState::*)> f) {
#define ENT(name, ...) f(&ArchState::name);
        if ((kind & REG)) {
            X_x86_REGS(ENT, ENT);
        }
        if ((kind & FLAG)) {
            X_x86_FLAGS(ENT, ENT);
        }
        if ((kind & XMM)) {
            X_x86_XMMS(ENT, ENT);
        }
#undef ENT
    }
    
    static void for_each_reg(std::function<void (z3::expr ArchState::*)> f) {
        for_each(REG, f);
    }
    static void for_each_flag(std::function<void (z3::expr ArchState::*)> f) {
        for_each(FLAG, f);
    }
    static void for_each_xmm(std::function<void (z3::expr ArchState::*)> f) {
        for_each(XMM, f);
    }
    static void for_each(std::function<void (z3::expr ArchState::*)> f) {
        for_each(ALL, f);
    }
    
#define ENT(...) 1 +
#define ENT_(...) 1
    static inline constexpr unsigned num_regs = X_x86_REGS(ENT, ENT_);
    static inline constexpr unsigned num_flags = X_x86_FLAGS(ENT, ENT_);
    static inline constexpr unsigned num_xmms = X_x86_XMMS(ENT, ENT_);
#undef ENT_
#undef ENT
    
    template <typename InputIt>
    void get_regs(InputIt begin, InputIt end, z3::expr_vector& v) const {
        for (auto it = begin; it != end; ++it) {
            v.push_back(this->**it);
        }
    }
    
    template <typename Container>
    void get_regs(const Container& reg_ptrs, z3::expr_vector& v) const {
        get_regs(std::begin(reg_ptrs), std::end(reg_ptrs), v);
    }
    
    template <typename InputIt>
    z3::expr_vector get_regs(InputIt begin, InputIt end) const {
        z3::expr_vector v {ctx()};
        get_regs(begin, end, v);
        return v;
    }
    
    template <typename Container>
    z3::expr_vector get_regs(const Container& reg_ptrs) {
        return get_regs(std::begin(reg_ptrs), std::end(reg_ptrs));
    }
    
    void stackdump(unsigned words, const z3::eval& eval) const;
    
    z3::expr get_pf(const z3::expr& x) const {
        return ~z3::bvredxor(x.extract(7, 0));
    }
    
    z3::expr get_sf(const z3::expr& x) const {
        const unsigned bits = x.get_sort().bv_size();
        return x.extract(bits - 1, bits - 1);
    }
    
    z3::expr get_zf(const z3::expr& x) const {
        return ~z3::bvredor(x);
    }
    
    void set_pf(const z3::expr& x) {
        pf = get_pf(x);
    }
    
    void set_sf(const z3::expr& x) {
        sf = get_sf(x);
    }
    
    void set_zf(const z3::expr& x) {
        zf = get_zf(x);
    }
    
    ArchState eval(const z3::model& model) const;
};

std::ostream& operator<<(std::ostream& os, const ArchState& arch);

}
