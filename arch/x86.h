#pragma once

#include <unordered_map>

#include <z3++.h>
#include <capstone/capstone.h>
#include "capstone++.h"

#include "xmacros.h"

namespace x86 {

#define X_x86_REGS(XB, XE)			\
    XB(eax)					\
    XB(ebx)					\
    XB(ecx)					\
    XB(edx)					\
    XB(edi)					\
    XB(esi)					\
    XB(ebp)					\
    XB(esp)					\
    XB(eip)					


#define X_x86_FLAGS(XB, XE)			\
  XB(cf)					\
  XB(zf)					\
  XE(sf)

  struct ArchState {
#define ENT_(name) z3::expr name
#define ENT(name) ENT_(name);
    X_x86_REGS(ENT, ENT_);
    X_x86_FLAGS(ENT, ENT_);
#undef ENT_
#undef ENT


#define ENT_(name) name(ctx)
#define ENT(name) ENT_(name),
    ArchState(z3::context& ctx): X_x86_REGS(ENT, ENT_) X_x86_FLAGS(ENT, ENT_) {
      zero();
    }
#undef ENT_
#undef ENT
    
    struct Sort;

    z3::context& ctx() { return eax.ctx(); }

    void zero() {
#define ENT_(name) name = ctx().bv_val(0, 32)
#define ENT(name) ENT_(name);
      X_x86_REGS(ENT, ENT_);
#undef ENT_
#undef ENT
#define ENT_(name) name = ctx().bv_val(0, 1)
#define ENT(name) ENT_(name);
      X_x86_FLAGS(ENT, ENT_);
#undef ENT_
#undef ENT
    }
  };

  std::ostream& operator<<(std::ostream& os, const ArchState& arch);

  struct ArchState::Sort {
    z3::sort reg;
    z3::func_decl cons;
    z3::sort sort;
    z3::func_decl_vector projs;

    enum class Fields { XM_LIST(X_x86_REGS) };
    
    Sort(z3::context& ctx);
    
    ArchState unpack(const z3::expr& e) const;
    z3::expr pack(ArchState& arch) const;
  };

  struct Register {
    x86_reg reg;

    Register(x86_reg reg): reg(reg) {}

    z3::expr operator()(ArchState& arch) const {
      switch (reg) {
      case X86_REG_EAX:
	return arch.eax;

      default:
	std::abort();
      }
    }

    void operator()(ArchState& arch, const z3::expr& e) const {
      switch (reg) {
      case X86_REG_EAX:
	arch.eax = e;
	break;

      default:
	std::abort();
      }
    }
  };

  struct Operand {
    const cs_x86_op& op;

    Operand(const cs_x86_op& op): op(op) {}
    
    z3::expr operator()(ArchState& arch) const;
    void operator()(ArchState& arch, const z3::expr& e) const;
  };

  struct Inst {
    cs_insn *I;
    cs_x86 *x86;

    Inst(cs_insn *I): I(I), x86(&I->detail->x86) {}
    
    void operator()(ArchState& arch) const { transfer(arch); }

    void transfer(ArchState& arch) const;

  private:
    z3::expr bool_to_bv(z3::context& ctx, const z3::expr& pred, unsigned n) const {
      return z3::ite(pred, ctx.bv_val(1, n), ctx.bv_val(0, n));
    }

    z3::expr bv_to_bool(z3::expr& bv, unsigned i) const {
      z3::context& ctx = bv.ctx();
      return bv.extract(i, i) == ctx.bv_val(1, 1);
    }

    void transfer_acc_src(ArchState& arch) const;
    
  };

  using addr_t = uint32_t;

  struct Program {
    cs::handle handle {CS_ARCH_X86, CS_MODE_32};
    std::vector<cs::insns> insns;
    std::unordered_map<addr_t, Inst> map;

    Program() {
      handle.detail(true);
    }
    
    std::size_t disasm(const uint8_t *data, std::size_t size, uint32_t address) {
      cs::insns new_insns;
      const std::size_t count = handle.disasm(data, size, address, new_insns);
      assert(new_insns.size() == count);
      for (cs_insn& new_insn : new_insns) {
	const Inst inst {&new_insn};
	map.emplace(new_insn.address, inst);
      }
      insns.push_back(std::move(new_insns));
      return count;
    }

    template <typename Container>
    std::size_t disasm(const Container& container, uint32_t address) {
      return disasm(container.data(), container.size() * sizeof(container.data()[0]), address);
    }
      
  };

}
