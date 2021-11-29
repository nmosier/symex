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
        case NP: return "NP";
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
        case NP: return arch.pf == 0;
        default: unimplemented("cc %s", str());
    }
}


void Inst::transfer(ArchState& arch, z3::solver& solver) const {
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
                     transfer_acc_src_arith(X86_INS_SUB, arch, ctx, zero, op.read(arch, solver), op.bits()),
                     solver);
            break;
        }

        case X86_INS_NOT: {
            const cs_x86_op& op = I->detail->x86.operands[0];
            const Operand op2 {op};
            const z3::expr res = ~op2.read(arch, solver);
            op2.write(arch, res, solver);
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
            transfer_acc_src(arch, solver);
            break;
            
        case X86_INS_MOV:
        case X86_INS_MOVDQU:
        case X86_INS_MOVDQA:
        case X86_INS_MOVAPS: {
            assert(x86->op_count == 2);
            const Operand dst {x86->operands[0]};
            const Operand src {x86->operands[1]};
            dst.write(arch, src.read(arch, solver), solver);
            break;
        }
            
        case X86_INS_MOVD:
        case X86_INS_MOVQ: {
            const Operand src {x86->operands[0]};
            const Operand dst {x86->operands[1]};
            z3::expr val = src.read(arch, solver);
            if (dst.bits() > src.bits()) {
                val = z3::zext(val, dst.bits() - src.bits());
            }
            if (src.bits() > dst.bits()) {
                val = val.extract(dst.bits() - 1, 0);
            }
            dst.write(arch, val, solver);
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
            dst.write(arch, f(src.read(arch, solver), dst.bits() - src.bits()), solver);
            break;
        }
            
        case X86_INS_CMOVS:
        case X86_INS_CMOVB:
        case X86_INS_CMOVE:
        case X86_INS_CMOVA:
        case X86_INS_CMOVNE:
        case X86_INS_CMOVGE:
        case X86_INS_CMOVNS: {
            using K = Condition::Kind;
            static const std::unordered_map<unsigned, Condition::Kind> cond_map = {
                {X86_INS_CMOVS,  K::S},
                {X86_INS_CMOVB,  K::B},
                {X86_INS_CMOVE,  K::E},
                {X86_INS_CMOVA,  K::A},
                {X86_INS_CMOVNE, K::NE},
                {X86_INS_CMOVGE, K::GE},
                {X86_INS_CMOVNS, K::NS},
            };
            const Condition cond {cond_map.at(I->id)};
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const z3::expr src = src_op.read(arch, solver);
            const z3::expr dst = dst_op.read(arch, solver);
            const z3::expr res = z3::ite(cond(arch), src, dst);
            dst_op.write(arch, res, solver);
            break;
        }
            
        case X86_INS_PMOVMSKB: {
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const unsigned src_bytes = src_op.bits() / 8;
            const z3::expr src = src_op.read(arch, solver);
            z3::expr_vector res {ctx};
            res.push_back(ctx.bv_val(0, dst_op.bits() - src_bytes));
            for (unsigned i = 0; i < src_bytes; ++i) {
                const unsigned byte = src_bytes - i - 1;
                const unsigned hi = (byte + 1) * 8 - 1;
                res.push_back(src.extract(hi, hi));
            }
            dst_op.write(arch, z3::concat(res), solver);
            break;
        }
            
        case X86_INS_BSF: {
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const z3::expr src = src_op.read(arch, solver);
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
            dst_op.write(arch, cur.front().val, solver);
            arch.zf = ~z3::bvredor(src);
            break;
        }
            
            
            
        case X86_INS_RET:
            eip = arch.mem.read(arch.esp, 4, solver);
            arch.esp = arch.esp + 4;
            break;
            
        case X86_INS_POP: {
            const Operand op {I->detail->x86.operands[0]};
            op.write(arch, arch.mem.read(arch.esp, 4, solver), solver);
            arch.esp = arch.esp + 4;
            break;
        }
            
        case X86_INS_PUSH: {
            const Operand op {I->detail->x86.operands[0]};
            arch.esp = arch.esp - 4;
            arch.mem.write(arch.esp, op.read(arch, solver), solver);
            break;
        }
            
        case X86_INS_CALL: {
            const Operand op {I->detail->x86.operands[0]};
            arch.esp = arch.esp - 4;
            arch.mem.write(arch.esp, arch.eip + I->size, solver);
            eip = op.read(arch, solver);
            break;
        }
            
        case X86_INS_JMP: {
            const Operand op {I->detail->x86.operands[0]};
            eip = op.read(arch, solver);
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
        case X86_INS_JNP:
            transfer_jcc(arch, ctx, solver);
            eip = arch.eip;
            break;
            
        case X86_INS_SETNE:
        case X86_INS_SETE:
        case X86_INS_SETG:
        case X86_INS_SETB: {
            const Operand acc_op {x86->operands[0]};
            using K = Condition::Kind;
            static const std::unordered_map<unsigned, K> map = {
                {X86_INS_SETNE, K::NE},
                {X86_INS_SETE,  K::E},
                {X86_INS_SETG,  K::G},
                {X86_INS_SETB,  K::B},
            };
            const Condition cond {map.at(I->id)};
            const z3::expr cc = cond(arch);
            // TODO: optimize by using sext instead?
            acc_op.write(arch, z3::ite(cc, ctx.bv_val(-1, 8), ctx.bv_val(0, 8)), solver);
            break;
        }
            
        case X86_INS_STOSD:
            transfer_string(arch, ctx, solver);
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
            transfer_shift(I->id, arch, ctx, solver);
            break;
            
        case X86_INS_PSRLDQ: {
            assert(x86->op_count == 2);
            const Operand acc {x86->operands[0]};
            const uint8_t imm = x86->operands[1].imm;
            const z3::expr acc_val = acc.read(arch, solver);
            const z3::expr res = z3::lshr(acc_val, imm);
            acc.write(arch, res, solver);
            break;
        }
            
        case X86_INS_MOVSB:
            transfer_string_rep(arch, ctx, solver);
            eip = arch.eip;
            break;
            
        case X86_INS_IMUL:
            transfer_imul(arch, ctx, solver);
            break;
            
        case X86_INS_DEC:
        case X86_INS_INC: {
            const Operand acc_op {x86->operands[0]};
            z3::expr acc = acc_op.read(arch, solver);
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
            
            acc_op.write(arch, res, solver);
            const unsigned hi = acc_op.bits() - 1;
            arch.zf = ~z3::bvredor(res);
            arch.sf = acc.extract(hi, hi);
            arch.set_pf(res);
            break;
        }
            
        case X86_INS_BT: {
            const Operand src_op {x86->operands[0]};
            const Operand bit_op {x86->operands[1]};
            const z3::expr src = src_op.read(arch, solver);
            z3::expr bit = bit_op.read(arch, solver);
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
            const z3::expr mem_val = mem_op.read(arch, size, solver);
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
            
            transfer_cmp(arch, acc_val, mem_val, solver); // this sets the flags properly

            const z3::expr eq = (mem_val == acc_val);
            mem_op.write(arch, z3::ite(eq, reg_op.read(arch), mem_val), solver);
            acc_op.write(arch, z3::ite(eq, acc_val, mem_val));
            break;
        }
            
        case X86_INS_XCHG: {
            assert(x86->op_count == 2);
            const Operand op1 {x86->operands[0]};
            const Operand op2 {x86->operands[1]};
            const z3::expr val1 = op1.read(arch, solver);
            const z3::expr val2 = op2.read(arch, solver);
            op1.write(arch, val2, solver);
            op2.write(arch, val1, solver);
            break;
        }
            
        case X86_INS_SBB: {
            assert(x86->op_count == 2);
            const Operand src_op {x86->operands[1]};
            const Operand acc_op {x86->operands[0]};
            const z3::expr src = src_op.read(arch, solver);
            const z3::expr acc = acc_op.read(arch, solver);
            const z3::expr carry = z3::zext(arch.cf, acc_op.bits() - 1);
            const z3::expr res = transfer_acc_src_arith(X86_INS_SUB, arch, ctx, acc, src + carry, acc_op.bits());
            acc_op.write(arch, res, solver);
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
            const z3::expr val = src.read(arch, solver);
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
            dst.write(arch, bv_val, solver);
            arch.fpu.pop();
            break;
        }
            
        case X86_INS_FILD: {
            assert(x86->op_count == 1);
            const Operand src {x86->operands[0]};
            const z3::expr int_val = src.read(arch, solver);
            const z3::expr fp_val = z3::sbv_to_fpa(int_val, arch.fpu.fp_sort());
            arch.fpu.push(fp_val);
            break;
        }
            
        case X86_INS_FMUL: {
            assert(x86->op_count == 1);
            const Register acc {X86_REG_ST0};
            const Operand src {x86->operands[0]};
            const z3::expr src_bv_val = src.read(arch, solver);
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
            const z3::expr val1 = op1.read(arch, solver);
            const z3::expr val2 = op2.read(arch);
            op1.write(arch, val2, solver);
            op2.write(arch, val1);
            break;
        }
            
        case X86_INS_XORPD:
        case X86_INS_XORPS: {
            assert(x86->op_count == 2);
            const Operand dst {x86->operands[0]};
            const Operand src {x86->operands[1]};
            const z3::expr val = src.read(arch, solver) ^ dst.read(arch, solver);
            dst.write(arch, val, solver);
            break;
        }
            
        case X86_INS_FNSTCW: {
            assert(x86->op_count == 1);
            const Operand dst {x86->operands[0]};
            const z3::expr src = arch.fpu.control;
            dst.write(arch, src, solver);
            break;
        }
            
        case X86_INS_FLDCW: {
            assert(x86->op_count == 1);
            const Operand src {x86->operands[0]};
            arch.fpu.control = src.read(arch, solver);
            break;
        }
          
        case X86_INS_FIST:
        case X86_INS_FISTP: {
            assert(x86->op_count == 1);
            static const std::unordered_map<int, bool> pop_map = {
                {X86_INS_FIST, false},
                {X86_INS_FISTP, true},
            };
            const bool pop = pop_map.at(I->id);
            const Operand dst {x86->operands[0]};
            const Register src {X86_REG_ST0};
            const z3::expr fp_val = src.read(arch);
            const z3::expr int_val = z3::fpa_to_sbv(fp_val, dst.bits());
            dst.write(arch, int_val, solver);
            if (pop) {
                arch.fpu.pop();
            }
            break;
        }
            
        case X86_INS_FADD: {
            assert(x86->op_count == 1);
            const Operand src {x86->operands[0]};
            const z3::expr src_bv_val = src.read(arch, solver);
            const z3::expr src_fp_val = arch.fpu.to_fp(src_bv_val);
            const Register acc {X86_REG_ST0};
            const z3::expr fp_res = acc.read(arch) + src_fp_val;
            acc.write(arch, fp_res);
            break;
        }
            
        case X86_INS_SIDT: {
            const Operand dst {x86->operands[0]};
            dst.write(arch, ctx.bv_val(0, 8 * 6), solver);
            break;
        }
            
        case X86_INS_CWD:
        case X86_INS_CDQ: {
            x86_reg src_reg, dst_reg;
            switch (I->id) {
                case X86_INS_CWD:
                    src_reg = X86_REG_AX;
                    dst_reg = X86_REG_DX;
                    break;
                case X86_INS_CDQ:
                    src_reg = X86_REG_EAX;
                    dst_reg = X86_REG_EDX;
                    break;
                default: std::abort();
            }
            const Register src {src_reg};
            const Register dst {dst_reg};
            const z3::expr src_val = src.read(arch);
            const unsigned bits = src_val.get_sort().bv_size();
            dst.write(arch, z3::sext(src_val.extract(bits - 1, bits - 1), bits - 1));
            break;
        }
            
        case X86_INS_IDIV: {
            const Operand src {x86->operands[0]};
            z3::expr src_val = src.read(arch, solver);
            const unsigned bits = src.bits();
            src_val = z3::sext(src_val, bits);
            static const std::unordered_map<unsigned, std::pair<x86_reg, x86_reg>> map = {
                {8, {X86_REG_AH, X86_REG_AL}},
                {16, {X86_REG_AX, X86_REG_DX}},
                {32, {X86_REG_EAX, X86_REG_EDX}},
            };
            const auto [r_hi, r_lo] = map.at(bits);
            const Register acc_hi {r_hi};
            const Register acc_lo {r_lo};
            const z3::expr acc_val = z3::concat(acc_hi.read(arch), acc_lo.read(arch));
            const z3::expr res = acc_val / src_val;
            acc_hi.write(arch, res.extract(bits * 2 - 1, bits));
            acc_lo.write(arch, res.extract(bits - 1, 0));
            break;
        }
            
        case X86_INS_SHLD: {
            const Operand dst {x86->operands[0]};
            const Operand src {x86->operands[1]};
            const Operand cnt {x86->operands[2]};
            assert(cnt.op.type != X86_OP_IMM);
            const z3::expr dst_val = dst.read(arch, solver);
            const z3::expr src_val = src.read(arch, solver);
            z3::expr cnt_val = cnt.read(arch, solver);
            cnt_val = cnt_val & ctx.bv_val(0b11111, cnt.bits());
            const z3::expr cnt_val_z = z3::zext(cnt_val, dst.bits() - cnt.bits());
            const z3::expr res = z3::concat(dst_val, src_val).extract(dst.bits() - 1, 0);
            dst.write(arch, res, solver);
            
            arch.cf = z3::bvsign(z3::shl(dst_val, cnt_val_z - 1));
            arch.of = z3::ite(cnt_val == 1,
                              dst_val.extract(dst.bits() - 1, dst.bits() - 1) ^
                              dst_val.extract(dst.bits() - 2, dst.bits() - 2),
                              ctx.bv_val(0, 1));
            arch.pf = z3::ite(cnt_val == 0, arch.pf, arch.get_pf(res));
            arch.sf = z3::ite(cnt_val == 0, arch.sf, arch.get_sf(res));
            arch.zf = z3::ite(cnt_val == 0, arch.zf, arch.get_zf(res));
            
            break;
        }
            
        case X86_INS_PINSRB:
        case X86_INS_PINSRD: {
            const Operand dst {x86->operands[0]};
            const Operand src {x86->operands[1]};
            const uint8_t imm = x86->operands[2].imm;
            z3::expr val = dst.read(arch, solver);
            assert(val.get_sort().bv_size() == 128);
        
            const z3::expr src_val = src.read(arch, solver);
            std::cerr << "val: " << val.get_sort().bv_size() << ", src_val: " << src_val.get_sort().bv_size() << ", lo: " << imm * src.bits() << "\n";
            const z3::expr res = z3::bv_store(val, src_val, imm * src.bits());
            dst.write(arch, res, solver);
            break;
        }
            
        case X86_INS_UCOMISD: {
            const Operand src1 {x86->operands[0]};
            const Operand src2 {x86->operands[1]};
            
            const unsigned bits = 64;
            
            z3::expr src1_val = src1.read(arch, solver);
            z3::expr src2_val = src2.read(arch, solver);
            
            /* truncate values */
            src1_val = z3::truncate(src1_val, bits);
            src2_val = z3::truncate(src2_val, bits);
            
            const auto& fp_spec = arch.fpu.fp_ieee_bits.at(bits);
            const z3::sort fp_sort = ctx.fpa_sort(fp_spec.first, fp_spec.second);
            src1_val = src1_val.mk_from_ieee_bv(fp_sort);
            src2_val = src2_val.mk_from_ieee_bv(fp_sort);
            
            const z3::expr unordered = z3::bool_to_bv(src1_val.mk_is_nan() || src2_val.mk_is_nan());
            
            /* set initial values */
            arch.cf = z3::bool_to_bv(src1_val < src2_val);
            arch.zf = z3::bool_to_bv(src1_val == src2_val);
            
            /* mask in unordered */
            arch.cf = arch.cf | unordered;
            arch.zf = arch.zf | unordered;
            arch.pf = unordered;
            
            /* reset other flags */
            arch.of = ctx.bv_val(0, 1);
            arch.sf = ctx.bv_val(0, 1);

            break;
        }

        default: unimplemented("%s", I->mnemonic);
    }
    
    // DEBUG
    arch.for_each_xmm([&] (const auto p) {
        assert((arch.*p).get_sort().bv_size() == 128);
    });
    
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
    arch.set_pf(res);
    
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
            arch.set_pf(res);
            break;
        case X86_INS_PXOR:
            break;
        default: unimplemented("%s", I->mnemonic);
    }
    
    return res;
}

// TODO: get rid of this.
void Inst::transfer_acc_src(ArchState& arch, z3::solver& solver) const {
    z3::context& ctx = arch.ctx();
    const Operand acc_op {I->detail->x86.operands[0]};
    const Operand src_op {I->detail->x86.operands[1]};
    z3::expr acc = acc_op.read(arch, solver);
    const z3::expr src = src_op.read(arch, solver);
    
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
            acc_op.write(arch, acc, solver);
            break;
            
        case X86_INS_TEST:
        case X86_INS_CMP:
            break;
            
        default: unimplemented("%s", I->mnemonic);
    }
}

void Inst::transfer_imul(ArchState& arch, z3::context& ctx, z3::solver& solver) const {
    switch (x86->op_count) {
        case 1:
        case 2:
            unimplemented("imul %s", I->op_str);
        case 3: {
            const Operand dst_op {x86->operands[0]};
            const Operand src_op {x86->operands[1]};
            const Operand imm_op {x86->operands[2]};
            z3::expr src = src_op.read(arch, solver);
            z3::expr imm = imm_op.read(arch, solver);
            const unsigned imm_sz = imm.get_sort().bv_size();
            const unsigned src_sz = src.get_sort().bv_size();
            const unsigned res_sz = src_sz * 2;
            imm = z3::sext(imm, res_sz - imm_sz);
            src = z3::sext(src, res_sz - src_sz);
            z3::expr res = src * imm;
            dst_op.write(arch, res.extract(src_sz - 1, 0), solver);
            arch.cf = res.extract(res_sz - 1, res_sz - 1) ^ res.extract(src_sz - 1, src_sz - 1);
            arch.of = arch.cf;
            break;
        }
            
            
        default: std::abort();
    }
}

void Inst::transfer_jcc(ArchState& arch, z3::context& ctx, z3::solver& solver) const {
    const Operand op {I->detail->x86.operands[0]};
    const z3::expr taken = op.read(arch, solver);
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
        {X86_INS_JNP, K::NP},
    };
    const Condition cond {cond_map.at(I->id)};
    
    arch.eip = z3::ite(cond(arch), taken, not_taken);
}

void Inst::transfer_cmovcc(ArchState& arch, z3::context& ctx, z3::solver& solver) const {
    const Operand dst {x86->operands[0]};
    const Operand src {x86->operands[1]};
    using K = Condition::Kind;
    static const std::unordered_map<unsigned, Condition::Kind> cond_map = {
        {X86_INS_CMOVA, K::A},
    };
    const Condition cond {cond_map.at(I->id)};
    const z3::expr value = z3::ite(cond(arch), src.read(arch, solver), dst.read(arch, solver));
    dst.write(arch, value, solver);
}

void Inst::transfer_string(ArchState& arch, z3::context& ctx, z3::solver& solver) const {
    const z3::expr four = ctx.bv_val(4, 32);
    switch (I->id) {
        case X86_INS_STOSD:
            arch.mem.write(arch.edi, arch.eax, solver);
            arch.edi = arch.edi + four;
            break;
        case X86_INS_MOVSB:
            arch.mem.write(arch.edi, arch.mem.read(arch.esi, 4, solver), solver);
            arch.esi = arch.esi + four;
            arch.edi = arch.edi + four;
            break;
        default:
            unimplemented("string %s", I->mnemonic);
    }
}

void Inst::transfer_string_rep(ArchState& arch, z3::context& ctx, z3::solver& solver) const {
    switch (x86->prefix[0]) {
        case X86_PREFIX_REP:
            transfer_string(arch, ctx, solver);
            arch.ecx = arch.ecx - ctx.bv_val(1, 32);
            arch.eip = z3::ite(arch.ecx == 0, arch.eip + I->size, arch.eip);
            break;
        default: unimplemented("prefix %02hhx", x86->prefix[0]);
    }
}

void Inst::transfer_shift(unsigned id, ArchState& arch, z3::context& ctx, z3::solver& solver) const {
    assert(x86->op_count == 2);
    const Operand acc_op {x86->operands[0]};
    const Operand shift_op {x86->operands[1]};
    const z3::expr acc = acc_op.read(arch, solver);
    z3::expr shift = shift_op.read(arch, solver);
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
    arch.set_pf(res);
    
    acc_op.write(arch, res, solver);
}

void Inst::transfer_cmp(ArchState& arch, const z3::expr& src1, const z3::expr& src2, z3::solver& solver) const {
    z3::context& ctx = src1.ctx();
    transfer_acc_src_arith(X86_INS_SUB, arch, ctx, src1, src2, src1.get_sort().bv_size());
}

}
