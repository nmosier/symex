#include <vector>

#include "capstone++.h"

#include "x86.h"

namespace x86 {

  ArchState::Sort::Sort(z3::context& ctx): reg(ctx.bv_sort(32)), cons(ctx), sort(ctx), projs(ctx) {
    constexpr std::size_t size = 10;
    const char *names[size] = { XM_STR_LIST(X_x86_REGS) };
    const std::vector<z3::sort> sorts {size, reg};
    cons = ctx.tuple_sort("x86_archstate", size, names, sorts.data(), projs);
    sort = cons.range();
  
  }

  ArchState ArchState::Sort::unpack(const z3::expr& e) const {
    ArchState arch {e.ctx()};
#define ENT(name) arch.name = projs[static_cast<unsigned>(Fields::name)](e);
    X_x86_REGS(ENT, ENT);
#undef ENT
    return arch;
  }

  z3::expr ArchState::Sort::pack(ArchState& arch) const {
    z3::expr_vector v {arch.ctx()};
#define ENT_(name) v.push_back(arch.name)
#define ENT(name) v.push_back(arch.name);
    X_x86_REGS(ENT, ENT_);
#undef ENT
#undef ENT_
    return cons(v);
  }

  // TRANSFER FUNCTIONS

  z3::expr Operand::operator()(ArchState& arch) const {
    switch (op.type) {
    case X86_OP_REG:
      return Register(op.reg)(arch);

    case X86_OP_IMM:
      return arch.ctx().bv_val(op.imm, op.size * 8);
      
    case X86_OP_MEM:
    default:
      std::abort();
    }
  }

  void Operand::operator()(ArchState& arch, const z3::expr& e) const {
    switch (op.type) {
    case X86_OP_REG:
      Register(op.reg)(arch, e);
      break;
      
    case X86_OP_IMM:
      throw std::logic_error("assignment to immediate");

    case X86_OP_MEM:
    default:
      std::abort();
    }
  }
  
  void Inst::transfer(ArchState& arch) const {
    z3::context& ctx = arch.ctx();
    const auto nops = x86->op_count;
    const auto *ops = x86->operands;
    switch (I->id) {
    case X86_INS_NOP:
      break;
    case X86_INS_NEG: {
      const cs_x86_op& op = I->detail->x86.operands[0];
      const Operand op2 {op};
      const z3::expr res = -op2(arch);
      op2(arch, res);
      arch.cf = z3::bvredor(res);
      break;
    }
    case X86_INS_NOT: {
      const cs_x86_op& op = I->detail->x86.operands[0];
      const Operand op2 {op};
      const z3::expr res = ~op2(arch);
      op2(arch, res);
      break;
    }
    case X86_INS_ADD:
    case X86_INS_SUB:
    case X86_INS_OR:
    case X86_INS_XOR:
      transfer_acc_src(arch);
      break;
    default:
      std::cerr << I->mnemonic << "\n";
      std::abort();
    }
  }
  
  void Inst::transfer_acc_src(ArchState& arch) const {
    z3::context& ctx = arch.ctx();
    const Operand acc {I->detail->x86.operands[0]};
    const Operand src {I->detail->x86.operands[1]};
    const z3::expr acc32 = acc(arch);
    const z3::expr src32 = src(arch);
    const z3::expr acc33 = concat(ctx.bv_val(0, 1), acc32);
    const z3::expr src33 = concat(ctx.bv_val(0, 1), src32);

    // TODO: factor common code out.
    switch (I->id) {
    case X86_INS_ADD: {
      z3::expr res33 = acc33 + src33;
      z3::expr res32 = res33.extract(31, 0);
      acc(arch, res32);
      arch.cf = res33.extract(32, 32);
      arch.zf = ~z3::bvredor(res32);
      arch.sf = res32.extract(31, 31);
      break;
    }

    case X86_INS_SUB: {
      z3::expr res33 = acc33 - src33;
      z3::expr res32 = res33.extract(31, 0);
      acc(arch, res32);
      arch.cf = res33.extract(32, 32);
      arch.zf = ~z3::bvredor(res32);
      arch.sf = res32.extract(31, 31);
      break;
    }

    case X86_INS_OR: {
      z3::expr res32 = acc32 | src32;
      acc(arch, res32);
      arch.cf = ctx.bv_val(0, 1);
      arch.zf = ~z3::bvredor(res32);
      arch.sf = res32.extract(31, 31);
      break;
    }

    case X86_INS_XOR: {
      z3::expr res32 = acc32 | src32;
      acc(arch, res32);
      arch.cf = ctx.bv_val(0, 1);
      arch.zf = ~z3::bvredor(res32);
      arch.sf = res32.extract(31, 31);
      break;
    }

    default:
      std::cerr << I->mnemonic << "\n";
      std::abort();
    }
  }
  
  std::ostream& operator<<(std::ostream& os, const ArchState& arch) {
#define ENT(name) os << #name << ": " << arch.name.simplify() << "\n";
    X_x86_REGS(ENT, ENT);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
    return os;
  }
  
}
