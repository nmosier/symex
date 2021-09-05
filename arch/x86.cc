#include <vector>

#include "capstone++.h"

#include "x86.h"
#include "util.h"

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

  z3::expr MemoryOperand::address(ArchState& arch) const {
    z3::context& ctx = arch.ctx();
      z3::expr base =
	mem.base == X86_REG_INVALID ? ctx.bv_val(0, 32) : Register(mem.base)(arch);
      z3::expr index =
	mem.index == X86_REG_INVALID ? ctx.bv_val(0, 32) : Register(mem.index)(arch);
      switch (mem.scale) {
      case 2:
      case 1:
      case 0:
	break;
      default:
	std::abort();
      }
      z3::expr index_scaled = z3::shl(index, mem.scale);
      z3::expr disp = ctx.bv_val(mem.disp, 32);
      z3::expr addr = base + index_scaled + disp;
      return addr;
  }

  z3::expr MemoryOperand::operator()(ArchState& arch, unsigned size) const {
    const z3::expr addr = address(arch);
    return arch.mem(addr, size);
  }

  void MemoryOperand::operator()(ArchState& arch, const z3::expr& e) const {
    const z3::expr addr = address(arch);
    return arch.mem.write(addr, e);
  }
  
  z3::expr Operand::operator()(ArchState& arch) const {
    z3::context& ctx = arch.ctx();
    const unsigned bits = op.size * 8;
    switch (op.type) {
    case X86_OP_REG:
      return Register(op.reg)(arch);

    case X86_OP_IMM:
      return ctx.bv_val(op.imm, bits);
      
    case X86_OP_MEM: {
      return MemoryOperand(op.mem)(arch, op.size);
    }
      
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
      MemoryOperand(op.mem)(arch, e);
      break;
      
    default: std::abort();
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
    case X86_INS_AND:
    case X86_INS_MOV:
      transfer_acc_src(arch);
      break;

    case X86_INS_RET:
      arch.eip = arch.mem(arch.esp, 4);
      arch.esp = arch.esp + 4;
      break;

    case X86_INS_POP: {
      const Operand op {I->detail->x86.operands[0]};
      op(arch, arch.mem(arch.esp, 4));
      arch.esp = arch.esp + 4;
      break;
    }

    case X86_INS_PUSH: {
      const Operand op {I->detail->x86.operands[0]};
      arch.esp = arch.esp - 4;
      arch.mem.write(arch.esp, op(arch));
      break;
    }

    case X86_INS_CALL: {
      const Operand op {I->detail->x86.operands[0]};
      arch.esp = arch.esp - 4;
      arch.mem.write(arch.esp, arch.eip + I->size);
      arch.eip = op(arch);
      break;
    }
      
    default:
      unimplemented("%s", I->mnemonic);
    }
  }

  void Inst::transfer_acc_src_arith(ArchState& arch, z3::context& ctx, const z3::expr& acc,
				    const z3::expr& src, unsigned bits, z3::expr& res) const {
    const z3::expr z = ctx.bv_val(0, 1);
    const z3::expr acc_z = concat(z, acc);
    const z3::expr src_z = concat(z, src);
    z3::expr res_x {ctx};

    switch (I->id) {
    case X86_INS_ADD:
      res_x = acc_z + src_z;
      break;

    case X86_INS_SUB:
      res_x = acc_z - src_z;
      break;

    default: std::abort();
    }

    res = res_x.extract(bits - 1, 0);

    // update flags
    arch.cf = res_x.extract(bits, bits);
    arch.zf = ~z3::bvredor(res);
    arch.sf = res.extract(bits - 1, bits - 1);
  }
  
  void Inst::transfer_acc_src_logic(ArchState& arch, z3::context& ctx, const z3::expr& acc,
				    const z3::expr& src, z3::expr& res) const {
    switch (I->id) {
    case X86_INS_AND:
      res = acc & src;
      break;
    case X86_INS_OR:
      res = acc | src;
      break;
    case X86_INS_XOR:
      res = acc ^ src;
      break;
    default: std::abort();
    }
  }
  
  void Inst::transfer_acc_src(ArchState& arch) const {
    z3::context& ctx = arch.ctx();
    const Operand acc_op {I->detail->x86.operands[0]};
    const Operand src_op {I->detail->x86.operands[1]};
    const z3::expr acc = acc_op(arch);
    const z3::expr src = src_op(arch);
    z3::expr res {ctx};

    switch (I->id) {
    case X86_INS_ADD:
    case X86_INS_SUB:
      transfer_acc_src_arith(arch, ctx, acc, src, acc_op.bits(), res);
      break;

    case X86_INS_OR:
    case X86_INS_AND:
    case X86_INS_XOR:
      transfer_acc_src_logic(arch, ctx, acc, src, res);
      break;

    case X86_INS_MOV:
      res = src;
      break;
      
    default:
      unimplemented("%s", I->mnemonic);
    }

    acc_op(arch, res);
  }
  
  std::ostream& operator<<(std::ostream& os, const ArchState& arch) {
#define ENT(name) os << #name << ": " << arch.name.simplify() << "\n";
    X_x86_REGS(ENT, ENT);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
    return os;
  }


  MemState::MemState(z3::context& ctx):
    mem1_sort(ctx), mem2_sort(ctx), mem4_sort(ctx),
    mem1(ctx), mem2(ctx), mem4(ctx)
  {
    const z3::sort bv8 = ctx.bv_sort(8);
    const z3::sort bv16 = ctx.bv_sort(16);
    const z3::sort bv32 = ctx.bv_sort(32);
    mem1_sort = ctx.array_sort(bv32, bv8);
    mem2_sort = ctx.array_sort(bv32, bv16);
    mem4_sort = ctx.array_sort(bv32, bv32);
    mem1 = ctx.constant("mem1", mem1_sort);
    mem2 = ctx.constant("mem2", mem2_sort);
    mem4 = ctx.constant("mem4", mem4_sort);
  }
  
  const z3::expr& MemState::mem(unsigned size) const {
    switch (size) {
    case 1: return mem1;
    case 2: return mem2;
    case 4: return mem4;
    default: std::abort();
    }
  }

  z3::expr& MemState::mem(unsigned size) {
    return const_cast<z3::expr&>(const_cast<const MemState&>(*this).mem(size));
  }

  z3::expr MemState::operator()(const z3::expr& address, unsigned size) const {
    return mem(size)[address];
  }


  z3::expr Register::operator()(ArchState& arch) const {
      switch (reg) {
      case X86_REG_EAX: return arch.eax;
      case X86_REG_ECX: return arch.ecx;
      case X86_REG_EDX: return arch.edx;

      case X86_REG_ESI: return arch.esi;

      case X86_REG_EBP: return arch.ebp;
      case X86_REG_ESP: return arch.esp;

      case X86_REG_CL: return arch.ecx.extract(7, 0);
	
      default:
	unimplemented("reg %s", cs_reg_name(g_handle, reg));
      }
    }
  
  void Register::operator()(ArchState& arch, const z3::expr& e) const {
      switch (reg) {
      case X86_REG_EAX: arch.eax = e; break;
      case X86_REG_ECX: arch.ecx = e; break;

      case X86_REG_ESI: arch.esi = e; break;
	
      case X86_REG_EBP: arch.ebp = e; break;
      case X86_REG_ESP: arch.esp = e; break;

      default:
	unimplemented("reg %s", cs_reg_name(g_handle, reg));
      }
  }


  void MemState::write(const z3::expr& address, const z3::expr& value) {
    const unsigned size = value.get_sort().bv_size() / 8;
    z3::expr& arr = mem(size);
    arr = z3::store(arr, address, value);
  }
  
}

