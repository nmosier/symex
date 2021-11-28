#include <optional>

#include "inst.h"
#include "util.h"
#include "operands.h"

namespace x86 {

const char *Condition::str() const {
    switch (kind) {
        case A:  return "A";
        case E:  return "E";
        case GE: return "GE";
        case NE: return "NE";
        case S:  return "S";
        case B:  return "B";
        case G:  return "G";
        case NS: return "NS";
        case LE: return "LE";
        case L:  return "L";
        case AE: return "AE";
        case BE: return "BE";
        default: unimplemented("cc %d", kind);
    }
}

z3::expr Condition::operator()(const ArchState& arch) const {
    switch (kind) {
        case A:  return arch.cf == 0 && arch.zf == 0;
        case E:  return arch.zf == 1;
        case GE: return arch.sf == arch.of;
        case NE: return arch.zf == 0;
        case S:  return arch.sf == 1;
        case B:  return arch.cf == 1;
        case G:  return arch.zf == 0 && arch.sf == arch.of;
        case NS: return arch.sf == 1;
        case LE: return arch.zf == 1 || arch.sf != arch.of;
        case L:  return arch.sf != arch.of;
        case AE: return arch.cf == 0;
        case BE: return (arch.cf | arch.zf) == 1;
        default: unimplemented("cc %s", str());
    }
}


void Inst::transfer(ArchState& arch, ReadOut read_out, WriteOut write_out) const {
    switch (I->id) {
        case X86_INS_PUSH:
        case X86_INS_MOV:
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_CALL:
        case X86_INS_POP:
        case X86_INS_TEST:
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR:
        case X86_INS_PXOR:
        case X86_INS_JE:
        case X86_INS_CMP:
        case X86_INS_LEA:
        case X86_INS_RET:
        case X86_INS_JGE:
        case X86_INS_JMP:
        case X86_INS_PCMPEQB:
        case X86_INS_SHL:
        case X86_INS_PMOVMSKB:
        case X86_INS_BSF:
        case X86_INS_NOP:
        case X86_INS_CMOVS:
        case X86_INS_CMOVB:
        case X86_INS_CMOVE:
        case X86_INS_JB:
        case X86_INS_JA:
        case X86_INS_SHR:
        case X86_INS_SETNE:
        case X86_INS_MOVZX:
        case X86_INS_JNE:
        case X86_INS_JG:
        case X86_INS_INC:
        case X86_INS_MOVSX:
        case X86_INS_JNS:
        case X86_INS_JLE:
        case X86_INS_JS:
        case X86_INS_DEC:
        case X86_INS_JL:
        case X86_INS_BT:
        case X86_INS_JAE:
        case X86_INS_CMPXCHG:
        case X86_INS_XCHG:
        case X86_INS_JBE:
        case X86_INS_NEG:
        case X86_INS_CMOVA:
        case X86_INS_MOVDQU:
        case X86_INS_MOVQ:
        case X86_INS_PSRLDQ:
        case X86_INS_MOVD:
        case X86_INS_SBB:
        case X86_INS_NOT:
        case X86_INS_CWDE:
        case X86_INS_IMUL:
        case X86_INS_FLD:
        case X86_INS_FSTP:
        case X86_INS_FILD:
        case X86_INS_FMUL:
        case X86_INS_CMOVNE:
        case X86_INS_CMOVGE:
        case X86_INS_SAR:
        case X86_INS_FLDZ:
        case X86_INS_FXCH:
            break;
            
        default: unimplemented("of %s", I->mnemonic);
    }
    
    
    z3::context& ctx = arch.ctx();
    std::optional<z3::expr> eip;
    const auto nops = x86->op_count;
    const auto *ops = x86->operands;
    switch (I->id) {
        case X86_INS_NOP:
            break;
            
        case X86_INS_NEG: {
            const Operand op {I->detail->x86.operands[0]};
            const z3::expr zero = ctx.bv_val(0, op.bits());
            op.write(arch,
                     transfer_acc_src_arith(X86_INS_SUB, arch, ctx, zero, op.read(arch, read_out), op.bits()),
                     write_out);
            break;
        }

        case X86_INS_NOT: {
            const cs_x86_op& op = I->detail->x86.operands[0];
            const Operand op2 {op};
            const z3::expr res = ~op2.read(arch, read_out);
            op2.write(arch, res, write_out);
            break;
        }
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_OR:
        case X86_INS_XOR:
        case X86_INS_AND:
        case X86_INS_TEST:
        case X86_INS_CMP:
        case X86_INS_PXOR:
        case X86_INS_PCMPEQB:
            transfer_acc_src(arch, read_out, write_out);
            break;
            
        case X86_INS_MOV:
        case X86_INS_MOVD:
        case X86_INS_MOVQ:
        case X86_INS_MOVDQU: {
            assert(x86->op_count == 2);
            const Operand dst {x86->operands[0]};
            const Operand src {x86->operands[1]};
            dst.write(arch, src.read(arch, read_out), write_out);
            break;
        }
            
        case X86_INS_MOVSX:
        case X86_INS_MOVZX: {
            const Operand dst {x86->operands[0]};
            const Operand src {x86->operands[1]};
            z3::expr (*f)(const z3::expr&, unsigned);
            switch (I->id) {
                case X86_INS_MOVSX: f = &z3::sext; break;
                case X86_INS_MOVZX: f = &z3::zext; break;
                default: unimplemented("%s", I->mnemonic);
            }
            dst.write(arch, f(src.read(arch, read_out), dst.bits() - src.bits()), write_out);
            break;
        }
            
        case X86_INS_CMOVS:
        case X86_INS_CMOVB:
        case X86_INS_CMOVE:
        case X86_INS_CMOVA:
        case X86_INS_CMOVNE:
        case X86_INS_CMOVGE: {
            using K = Condition::Kind;
            static const std::unordered_map<unsigned, Condition::Kind> cond_map = {
                {X86_INS_CMOVS,  K::S},
                {X86_INS_CMOVB,  K::B},
                {X86_INS_CMOVE,  K::E},
                {X86_INS_CMOVA,  K::A},
                {X86_INS_CMOVNE, K::NE},
                {X86_INS_CMOVGE, K::GE},
            };
            const Condition cond {cond_map.at(I->id)};
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const z3::expr src = src_op.read(arch, read_out);
            const z3::expr dst = dst_op.read(arch, read_out);
            const z3::expr res = z3::ite(cond(arch), src, dst);
            dst_op.write(arch, res, write_out);
            break;
        }
            
        case X86_INS_PMOVMSKB: {
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const unsigned src_bytes = src_op.bits() / 8;
            const z3::expr src = src_op.read(arch, read_out);
            z3::expr_vector res {ctx};
            res.push_back(ctx.bv_val(0, dst_op.bits() - src_bytes));
            for (unsigned i = 0; i < src_bytes; ++i) {
                const unsigned byte = src_bytes - i - 1;
                const unsigned hi = (byte + 1) * 8 - 1;
                res.push_back(src.extract(hi, hi));
            }
            dst_op.write(arch, z3::concat(res), write_out);
            break;
        }
            
        case X86_INS_BSF: {
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const z3::expr src = src_op.read(arch, read_out);
            struct Entry {
                z3::expr one;
                z3::expr val;
                Entry(const z3::expr& one, const z3::expr& val): one(one), val(val) {}
            };
            std::vector<Entry> cur;
            for (unsigned i = 0; i < src.get_sort().bv_size(); ++i) {
                cur.emplace_back(src.extract(i, i) == ctx.bv_val(1, 1), ctx.bv_val(i, dst_op.bits()));
            }
            while (cur.size() > 1) {
                std::vector<Entry> next;
                for (unsigned i = 0; i < cur.size(); i += 2) {
                    const auto& left = cur[i];
                    const auto& right = cur[i + 1];
                    next.emplace_back(left.one || right.one, z3::ite(right.one, right.val, left.val));
                }
                cur = std::move(next);
            }
            dst_op.write(arch, cur.front().val, write_out);
            arch.zf = ~z3::bvredor(src);
            break;
        }
            
            
            
        case X86_INS_RET:
            eip = arch.mem.read(arch.esp, 4, read_out);
            arch.esp = arch.esp + 4;
            break;
            
        case X86_INS_POP: {
            const Operand op {I->detail->x86.operands[0]};
            op.write(arch, arch.mem.read(arch.esp, 4, read_out), write_out);
            arch.esp = arch.esp + 4;
            break;
        }
            
        case X86_INS_PUSH: {
            const Operand op {I->detail->x86.operands[0]};
            arch.esp = arch.esp - 4;
            arch.mem.write(arch.esp, op.read(arch, read_out), write_out);
            break;
        }
            
        case X86_INS_CALL: {
            const Operand op {I->detail->x86.operands[0]};
            arch.esp = arch.esp - 4;
            arch.mem.write(arch.esp, arch.eip + I->size, write_out);
            eip = op.read(arch, read_out);
            break;
        }
            
        case X86_INS_JMP: {
            const Operand op {I->detail->x86.operands[0]};
            eip = op.read(arch, read_out);
            break;
        }
            
        case X86_INS_JE:
        case X86_INS_JB:
        case X86_INS_JA:
        case X86_INS_JAE:
        case X86_INS_JGE:
        case X86_INS_JNE:
        case X86_INS_JG:
        case X86_INS_JNS:
        case X86_INS_JLE:
        case X86_INS_JS:
        case X86_INS_JL:
        case X86_INS_JBE:
            transfer_jcc(arch, ctx, read_out, write_out);
            eip = arch.eip;
            break;
            
        case X86_INS_SETNE: {
            const Operand acc_op {x86->operands[0]};
            using K = Condition::Kind;
            static const std::unordered_map<unsigned, K> map = {
                {X86_INS_SETNE, K::NE},
            };
            const Condition cond {map.at(I->id)};
            const z3::expr cc = cond(arch);
            // TODO: optimize by using sext instead?
            acc_op.write(arch, z3::ite(cc, ctx.bv_val(-1, 8), ctx.bv_val(0, 8)), write_out);
            break;
        }
            
        case X86_INS_STOSD:
            transfer_string(arch, ctx, read_out, write_out);
            break;
            
        case X86_INS_LEA: {
            const Register dst {x86->operands[0].reg};
            const MemoryOperand src {x86->operands[1].mem};
            dst.write(arch, src.addr(arch));
            break;
        }
            
        case X86_INS_SHR:
        case X86_INS_SHL:
        case X86_INS_SAR:
            transfer_shift(I->id, arch, ctx, read_out, write_out);
            break;
            
        case X86_INS_PSRLDQ:
            assert(x86->op_count == 2);
            transfer_shift(X86_INS_SHR, arch, ctx, read_out, write_out);
            break;
            
        case X86_INS_MOVSB:
            transfer_string_rep(arch, ctx, read_out, write_out);
            eip = arch.eip;
            break;
            
        case X86_INS_IMUL:
            transfer_imul(arch, ctx, read_out, write_out);
            break;
            
        case X86_INS_DEC:
        case X86_INS_INC: {
            const Operand acc_op {x86->operands[0]};
            z3::expr acc = acc_op.read(arch, read_out);
            z3::expr res {ctx};
            const z3::expr overflow = z3::concat(ctx.bv_val(1, 1), ctx.bv_val(0, acc_op.bits() - 1));
            switch (I->id) {
                case X86_INS_DEC:
                    res = acc - 1;
                    arch.of = z3::bool_to_bv(acc == overflow);
                    break;
                    
                case X86_INS_INC:
                    res = acc + 1;
                    arch.of = z3::bool_to_bv(acc == ~overflow);
                    break;
                    
                default: unimplemented("%s", I->mnemonic);
            }
            
            acc_op.write(arch, res, write_out);
            const unsigned hi = acc_op.bits() - 1;
            arch.zf = ~z3::bvredor(res);
            arch.sf = acc.extract(hi, hi);
            break;
        }
            
        case X86_INS_BT: {
            const Operand src_op {x86->operands[0]};
            const Operand bit_op {x86->operands[1]};
            const z3::expr src = src_op.read(arch, read_out);
            z3::expr bit = bit_op.read(arch, read_out);
            assert(bit_op.size() <= src_op.size());
            if (bit_op.size() < src_op.size()) {
                bit = z3::zext(bit, src_op.bits() - bit_op.bits());
            }
            arch.cf = z3::lshr(src, bit).extract(0, 0);
            break;
        }
            
        case X86_INS_CMPXCHG: {
            assert(x86->op_count == 2);
            const unsigned size = x86->operands[0].size;
            const MemoryOperand mem_op {x86->operands[0].mem};
            const Register reg_op {x86->operands[1].reg};
            const z3::expr mem_val = mem_op.read(arch, size, read_out);
            x86_reg acc_reg;
            switch (size) {
                case 1:
                    acc_reg = X86_REG_AL;
                    break;
                case 2:
                    acc_reg = X86_REG_AX;
                    break;
                case 4:
                    acc_reg = X86_REG_EAX;
                    break;
                default: std::abort();
            }
            const Register acc_op {acc_reg};
            const z3::expr acc_val = acc_op.read(arch);
            const z3::expr eq = (mem_val == acc_val);
            arch.zf = z3::bool_to_bv(eq);
            mem_op.write(arch, z3::ite(eq, reg_op.read(arch), mem_val), write_out);
            acc_op.write(arch, z3::ite(eq, acc_val, mem_val));
            break;
        }
            
        case X86_INS_XCHG: {
            assert(x86->op_count == 2);
            const Operand op1 {x86->operands[0]};
            const Operand op2 {x86->operands[1]};
            const z3::expr val1 = op1.read(arch, read_out);
            const z3::expr val2 = op2.read(arch, read_out);
            op1.write(arch, val2, write_out);
            op2.write(arch, val1, write_out);
            break;
        }
            
        case X86_INS_SBB: {
            assert(x86->op_count == 2);
            const Operand src_op {x86->operands[1]};
            const Operand acc_op {x86->operands[0]};
            const z3::expr src = src_op.read(arch, read_out);
            const z3::expr acc = acc_op.read(arch, read_out);
            const z3::expr carry = z3::zext(arch.cf, acc_op.bits() - 1);
            const z3::expr res = transfer_acc_src_arith(X86_INS_SUB, arch, ctx, acc, src + carry, acc_op.bits());
            acc_op.write(arch, res, write_out);
            break;
        }
            
        case X86_INS_CWDE: {
            assert(x86->op_count == 0);
            const Register src {X86_REG_AX};
            const Register dst {X86_REG_EAX};
            const z3::expr val = z3::sext(src.read(arch), 16);
            dst.write(arch, val);
            break;
        }
            
        case X86_INS_FLD: {
            assert(x86->op_count == 1);
            const auto& op = x86->operands[0];
            assert(op.type != X86_OP_IMM);
            const Operand src {op};
            const z3::expr val = src.read(arch, read_out);
            arch.fpu.push(val);
            break;
        }
            
        case X86_INS_FSTP: {
            assert(x86->op_count == 1);
            const auto& op = x86->operands[0];
            assert(op.type != X86_OP_IMM);
            const Operand dst {op};
            const z3::expr fp_val = arch.fpu.get(0);
            const z3::expr bv_val = arch.fpu.to_bv(fp_val, dst.bits());
            dst.write(arch, bv_val, write_out);
            arch.fpu.pop();
            break;
        }
            
        case X86_INS_FILD: {
            assert(x86->op_count == 1);
            const Operand src {x86->operands[0]};
            const z3::expr int_val = src.read(arch, read_out);
            const z3::expr fp_val = z3::sbv_to_fpa(int_val, arch.fpu.fp_sort());
            arch.fpu.push(fp_val);
            break;
        }
            
        case X86_INS_FMUL: {
            assert(x86->op_count == 1);
            const Register acc {X86_REG_ST0};
            const Operand src {x86->operands[0]};
            const z3::expr src_bv_val = src.read(arch, read_out);
            const z3::expr src_fp_val = arch.fpu.to_fp(src_bv_val);
            const z3::expr res = acc.read(arch) * src_fp_val;
            acc.write(arch, res);
            break;
        }
            
        case X86_INS_FLDZ: {
            assert(x86->op_count == 0);
            arch.fpu.push(arch.fpu.to_fp(ctx.fpa_val(0.)));
            break;
        }
            
        case X86_INS_FXCH: {
            assert(x86->op_count == 1);
            const Operand op1 {x86->operands[0]};
            const Register op2 {X86_REG_ST0};
            const z3::expr val1 = op1.read(arch, read_out);
            const z3::expr val2 = op2.read(arch);
            op1.write(arch, val2, write_out);
            op2.write(arch, val1);
            break;
        }
            
        default: unimplemented("%s", I->mnemonic);
    }
    
    if (!eip) {
        eip = (arch.eip + I->size).simplify();
    }
    arch.eip = *eip;
}

z3::expr Inst::transfer_acc_src_arith(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                  const z3::expr& src, unsigned bits) const {
    z3::expr res {ctx};
    z3::expr res_x {ctx};
    
    switch (id) {
        case X86_INS_ADD: {
            res_x = z3::zext(acc, 1) + z3::zext(src, 1);
            res = res_x.extract(bits - 1, 0);
            arch.of = z3::bool_to_bv(z3::bvsign(acc) == z3::bvsign(src) && z3::bvsign(res) != z3::bvsign(acc));
            break;
        }
            
        case X86_INS_SUB:
            res_x = z3::zext(acc, 1) - z3::zext(src, 1);
            res = res_x.extract(bits - 1, 0);
            arch.of = z3::bool_to_bv(z3::bvsign(acc) != z3::bvsign(src) && z3::bvsign(res) != z3::bvsign(acc));
            break;
            
        default: unimplemented("%s", I->mnemonic);
    }
    
    arch.cf = res_x.extract(bits, bits);
    arch.zf = ~z3::bvredor(res);
    arch.sf = z3::bvsign(res);
    
    return res;
}

z3::expr Inst::transfer_acc_src_logic(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                  const z3::expr& src, unsigned bits) const {
    z3::expr res {ctx};
    
    switch (id) {
        case X86_INS_AND:
            res = acc & src;
            break;
        case X86_INS_OR:
            res = (acc | src);
            res = (acc | src);
            break;
        case X86_INS_XOR:
        case X86_INS_PXOR:
            res = acc ^ src;
            break;
        default: unimplemented("%s", I->mnemonic);
    }
    
    // update flags
    switch (id) {
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR:
            arch.cf = ctx.bv_val(0, 1);
            arch.zf = ~z3::bvredor(res);
            arch.sf = res.extract(bits - 1, bits - 1);
            arch.of = ctx.bv_val(0, 1);
            break;
        case X86_INS_PXOR:
            break;
        default: unimplemented("%s", I->mnemonic);
    }
    
    return res;
}

void Inst::transfer_acc_src(ArchState& arch, ReadOut read_out, WriteOut write_out) const {
    z3::context& ctx = arch.ctx();
    const Operand acc_op {I->detail->x86.operands[0]};
    const Operand src_op {I->detail->x86.operands[1]};
    z3::expr acc = acc_op.read(arch, read_out);
    const z3::expr src = src_op.read(arch, read_out);
    
    switch (I->id) {
        case X86_INS_ADD:
        case X86_INS_SUB:
            acc = transfer_acc_src_arith(I->id, arch, ctx, acc, src, acc_op.bits());
            break;
            
        case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_XOR:
        case X86_INS_PXOR:
            acc = transfer_acc_src_logic(I->id, arch, ctx, acc, src, acc_op.bits());
            break;
            
        case X86_INS_TEST:
            transfer_acc_src_logic(X86_INS_AND, arch, ctx, acc, src, acc_op.bits());
            break;
            
        case X86_INS_CMP:
            transfer_acc_src_arith(X86_INS_SUB, arch, ctx, acc, src, acc_op.bits());
            break;
            
        case X86_INS_PCMPEQB: {
            z3::expr_vector res {ctx};
            for (unsigned i = 0; i < acc.get_sort().bv_size(); i += 8) {
                const unsigned hi = 32 - i - 1;
                const unsigned lo = 32 - i - 8;
                res.push_back(acc.extract(hi, lo) == src.extract(hi, lo) ? ctx.bv_val(-1, 8) : ctx.bv_val(0, 8));
            }
            acc = z3::concat(res);
            break;
        }
            
            
        default:
            unimplemented("%s", I->mnemonic);
    }
    
    switch (I->id) {
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_XOR:
        case X86_INS_PXOR:
        case X86_INS_PCMPEQB:
            acc_op.write(arch, acc, write_out);
            break;
            
        case X86_INS_TEST:
        case X86_INS_CMP:
            break;
            
        default: unimplemented("%s", I->mnemonic);
    }
}

void Inst::transfer_imul(ArchState& arch, z3::context& ctx, ReadOut read_out, WriteOut write_out) const {
    switch (x86->op_count) {
        case 1:
        case 2:
            unimplemented("imul %s", I->op_str);
        case 3: {
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const Operand imm_op {x86->operands[2]};
            z3::expr src = src_op.read(arch, read_out);
            z3::expr imm = imm_op.read(arch, read_out);
            const unsigned imm_sz = imm.get_sort().bv_size();
            const unsigned src_sz = src.get_sort().bv_size();
            const unsigned res_sz = src_sz * 2;
            imm = z3::sext(imm, res_sz - imm_sz);
            src = z3::sext(src, res_sz - src_sz);
            z3::expr res = src * imm;
            dst_op.write(arch, res.extract(src_sz - 1, 0), write_out);
            arch.cf = res.extract(res_sz - 1, res_sz - 1) ^ res.extract(src_sz - 1, src_sz - 1);
            arch.of = arch.cf;
            break;
        }
            
            
        default: std::abort();
    }
}

void Inst::transfer_jcc(ArchState& arch, z3::context& ctx, ReadOut read_out, WriteOut write_out) const {
    const Operand op {I->detail->x86.operands[0]};
    const z3::expr taken = op.read(arch, read_out);
    const z3::expr not_taken = arch.eip + ctx.bv_val(I->size, 32);
    const z3::expr zero = ctx.bv_val(0, 1);
    const z3::expr one = ctx.bv_val(1, 1);
    using K = Condition::Kind;
    static const std::unordered_map<unsigned, Condition::Kind> cond_map = {
        {X86_INS_JE,  K::E},
        {X86_INS_JGE, K::GE},
        {X86_INS_JNE, K::NE},
        {X86_INS_JA,  K::A},
        {X86_INS_JB,  K::B},
        {X86_INS_JG,  K::G},
        {X86_INS_JNS, K::NS},
        {X86_INS_JLE, K::LE},
        {X86_INS_JS,  K::S},
        {X86_INS_JL,  K::L},
        {X86_INS_JAE, K::AE},
        {X86_INS_JBE, K::BE},
    };
    const Condition cond {cond_map.at(I->id)};
    
    arch.eip = z3::ite(cond(arch), taken, not_taken);
}

void Inst::transfer_cmovcc(ArchState& arch, z3::context& ctx, ReadOut read_out, WriteOut write_out) const {
    const Operand dst {x86->operands[0]};
    const Operand src {x86->operands[1]};
    using K = Condition::Kind;
    static const std::unordered_map<unsigned, Condition::Kind> cond_map = {
        {X86_INS_CMOVA, K::A},
    };
    const Condition cond {cond_map.at(I->id)};
    const z3::expr value = z3::ite(cond(arch), src.read(arch, read_out), dst.read(arch, read_out));
    dst.write(arch, value, write_out);
}

void Inst::transfer_string(ArchState& arch, z3::context& ctx, ReadOut read_out, WriteOut write_out) const {
    const z3::expr four = ctx.bv_val(4, 32);
    switch (I->id) {
        case X86_INS_STOSD:
            arch.mem.write(arch.edi, arch.eax, write_out);
            arch.edi = arch.edi + four;
            break;
        case X86_INS_MOVSB:
            arch.mem.write(arch.edi, arch.mem.read(arch.esi, 4, read_out), write_out);
            arch.esi = arch.esi + four;
            arch.edi = arch.edi + four;
            break;
        default:
            unimplemented("string %s", I->mnemonic);
    }
}

void Inst::transfer_string_rep(ArchState& arch, z3::context& ctx, ReadOut read_out, WriteOut write_out) const {
    switch (x86->prefix[0]) {
        case X86_PREFIX_REP:
            transfer_string(arch, ctx, read_out, write_out);
            arch.ecx = arch.ecx - ctx.bv_val(1, 32);
            arch.eip = z3::ite(arch.ecx == 0, arch.eip + I->size, arch.eip);
            break;
        default: unimplemented("prefix %02hhx", x86->prefix[0]);
    }
}

void Inst::transfer_shift(unsigned id, ArchState& arch, z3::context& ctx, ReadOut read_out, WriteOut write_out) const {
    assert(x86->op_count == 2);
    const Operand acc_op {x86->operands[0]};
    const Operand shift_op {x86->operands[1]};
    const z3::expr acc = acc_op.read(arch, read_out);
    z3::expr shift = shift_op.read(arch, read_out);
    assert(acc.get_sort().bv_size() >= shift.get_sort().bv_size());
    shift = z3::zext(shift, acc.get_sort().bv_size() - shift.get_sort().bv_size());
    z3::expr res {ctx};
    switch (id) {
        case X86_INS_SHL:
            res = z3::shl(acc, shift);
            arch.cf = z3::bvsign(z3::shl(acc, shift - 1));
            arch.of = acc.extract(acc_op.bits() - 1, acc_op.bits() - 1) ^ acc.extract(acc_op.bits() - 2, acc_op.bits() - 2);
            break;
            
        case X86_INS_SHR:
            res = z3::lshr(acc, shift);
            arch.cf = z3::lshr(acc, shift - 1).extract(0, 0);
            arch.of = z3::bvsign(acc);
            break;
            
        case X86_INS_SAR:
            res = z3::ashr(acc, shift);
            arch.cf = z3::ashr(acc, shift - 1).extract(0, 0);
            arch.of = ctx.bv_val(0, 1);
            break;
            
        default: unimplemented("shift %s", I->op_str);
    }
    
    arch.sf = z3::bvsign(res);
    arch.zf = ~z3::bvredor(res);
    
    acc_op.write(arch, res, write_out);
}

}
