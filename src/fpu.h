#pragma once

#include <vector>
#include <unordered_map>

#include <z3++.h>

namespace x86 {

struct FPUState {
    z3::expr stack;
    z3::expr size;
    z3::expr control; // 16 bits
    
    static inline constexpr unsigned SINGLE_PREC_WIDTH = 32;
    static inline constexpr unsigned DOUBLE_PREC_WIDTH = 64;
    static inline constexpr unsigned EXTENDED_PREC_WIDTH = 80;
    
    FPUState(z3::context& ctx): stack(ctx), size(ctx), control(ctx) {
        stack = z3::const_array(ctx.int_sort(), ctx.fpa_nan(fp_sort()));
        size = ctx.int_val(0);
        control = ctx.bv_val(0x037F, 16);
    }
    
    static const std::unordered_map<unsigned, std::pair<unsigned, unsigned>> fp_ieee_bits;
    
    z3::context& ctx() const {
        return stack.ctx();
    }
    
    z3::sort fp_sort() const {
        const auto& spec = fp_ieee_bits.at(EXTENDED_PREC_WIDTH);
        return ctx().fpa_sort(spec.first, spec.second);
    }
    
    void push(const z3::expr& e) {
        stack[size] = to_fp(e);
        size = size + 1;
    }
    
    z3::expr pop() {
        size = size - 1;
        return stack[size];
    }
    
    z3::expr get(unsigned i) const {
        check_idx(i);
        return stack[size - ctx().int_val(i + 1)];
    }
    
    void set(unsigned i, const z3::expr& e_) {
        check_idx(i);
        const z3::expr e = to_fp(e_);
        stack = z3::store(stack, size - ctx().int_val(i + 1), e);
    }
    
    z3::expr to_fp(const z3::expr& e_) const {
        z3::expr e = e_;
        if (e.is_bv()) {
            const auto& spec = fp_ieee_bits.at(e.get_sort().bv_size());
            const z3::sort sort = ctx().fpa_sort(spec.first, spec.second);
            e = e.mk_from_ieee_bv(sort);
        }
        
        if (!e.is_fpa()) {
            throw std::invalid_argument("expression isn't a bitvector or floating-point");
        }
        
        const z3::sort fp_sort = this->fp_sort();
        const z3::sort& e_sort = e.get_sort();
        if (e_sort.fpa_ebits() != fp_sort.fpa_ebits() || e_sort.fpa_sbits() != fp_sort.fpa_sbits()) {
            e = z3::fpa_to_fpa(e, fp_sort);
        }
        
        return e;
    }
    
    z3::expr to_bv(const z3::expr& fp, unsigned bv_bits) const {
        if (fp.is_bv()) {
            return fp;
        } else if (fp.is_fpa()) {
            const auto& in_sort = fp.get_sort();
            const auto in_bits = in_sort.fpa_ebits() + in_sort.fpa_sbits();
            const auto& out_spec = fp_ieee_bits.at(bv_bits);
            const z3::sort out_sort = ctx().fpa_sort(out_spec.first, out_spec.second);
            const z3::expr out_fp = z3::fpa_to_fpa(fp, out_sort);
            return out_fp.mk_to_ieee_bv();
        } else {
            throw std::invalid_argument("FPUState::to_bv: expression isn't floating-point");
        }
    }
    
private:
    void check_idx(unsigned i) const {
        if (i >= 8) {
            throw std::out_of_range("bad FPU index");
        }
    }
    
    
};

}
