#pragma once

#include "archstate.h"
#include "operands.h"

namespace x86 {

struct Inst {
    cs_insn *I;
    cs_x86 *x86;
    
    Inst(cs_insn *I): I(I), x86(&I->detail->x86) {}
    
    using ReadOut = std::back_insert_iterator<std::vector<MemState::Read>>;
    using WriteOut = std::back_insert_iterator<std::vector<MemState::Write>>;
    
    void transfer(ArchState& arch, z3::solver& solver) const;
    
    bool operator<(const Inst& other) const {
        return I < other.I;
    }
    
    bool has_multiple_exits() const {
        switch (I->id) {
            case X86_INS_JAE:
            case X86_INS_JA:
            case X86_INS_JBE:
            case X86_INS_JB:
            case X86_INS_JCXZ:
            case X86_INS_JECXZ:
            case X86_INS_JE:
            case X86_INS_JGE:
            case X86_INS_JG:
            case X86_INS_JLE:
            case X86_INS_JL:
            case X86_INS_JNE:
            case X86_INS_JNO:
            case X86_INS_JNP:
            case X86_INS_JNS:
            case X86_INS_JO:
            case X86_INS_JP:
            case X86_INS_JRCXZ:
            case X86_INS_JS:
            case X86_INS_RET:
                return true;
                
            case X86_INS_JMP:
            case X86_INS_CALL:
                switch (x86->operands[0].type) {
                    case X86_OP_MEM:
                    case X86_OP_REG:
                        return true;
                    default:
                        return false;
                }
                
            default:
                return false;
        }
    }
    
private:
    z3::expr bool_to_bv(z3::context& ctx, const z3::expr& pred, unsigned n) const {
        return z3::ite(pred, ctx.bv_val(1, n), ctx.bv_val(0, n));
    }
    
    z3::expr bv_to_bool(z3::expr& bv, unsigned i) const {
        z3::context& ctx = bv.ctx();
        return bv.extract(i, i) == ctx.bv_val(1, 1);
    }
    
    void transfer_acc_src(ArchState& arch, z3::solver& solver) const;
    z3::expr transfer_acc_src_arith(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                const z3::expr& src, unsigned bits) const;
    z3::expr transfer_acc_src_logic(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                const z3::expr& src, unsigned bits) const;
    void transfer_jcc(ArchState& arch, z3::context& ctx, z3::solver& solver) const;
    void transfer_cmovcc(ArchState& arch, z3::context& ctx, z3::solver& solver) const;
    void transfer_string(ArchState& arch, z3::context& ctx, z3::solver& solver) const;
    void transfer_string_rep(ArchState& arch, z3::context& ctx, z3::solver& solver) const;
    void transfer_shift(unsigned id, ArchState& arch, z3::context& ctx, z3::solver& solver) const;
    void transfer_imul(ArchState& arch, z3::context& ctx, z3::solver& solver) const;
    void transfer_mul(ArchState& arch, z3::context& ctx, z3::solver& solver) const;
    void transfer_mul_imul_1(ArchState& arch, z3::context& ctx, z3::solver& solver, z3::expr (*ext)(const z3::expr&, unsigned)) const;
    void transfer_cmp(ArchState& arch, const z3::expr& src1, const z3::expr& src2, z3::solver& solver) const;
    z3::expr transfer_rotate_left(ArchState& arch, const z3::expr& acc, const z3::expr& cnt) const;
};

inline std::ostream& operator<<(std::ostream& os, const Inst& x) {
    os << std::hex << x.I->address << " " << x.I->mnemonic << " " << x.I->op_str;
    return os;
}

struct Condition {
    enum Kind {
        A, // above
        E, // equal
        GE, // greater than or equal
        NE, // not equal
        S, // SF == 1
        B, // CF == 1
        G, // greater
        NS, // SF == 0
        LE, // ZF == 1 || SF != OF
        L,
        AE, // CF == 0
        BE, // CF == 1 || ZF == 1
        NP, // PF == 0
    } kind;
    
    Condition(Kind kind): kind(kind) {}
    
    const char *str() const;
    
    z3::expr operator()(const ArchState& arch) const;
};



}
