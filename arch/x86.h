#pragma once

#include <map>
#include <array>
#include <unordered_map>
#include <unordered_set>

#include <z3++.h>
#include <capstone/capstone.h>
#include "capstone++.h"

#include "xmacros.h"
#include "util.h"

extern csh g_handle;

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
    XE(eip)					


#define X_x86_FLAGS(XB, XE)			\
  XB(cf)					\
  XB(zf)					\
  XE(sf)

#define X_x86_MEMS(XB, XE)			\
  XB(mem1)						\
  XB(mem2)						\
  XB(mem4)

  struct MemState {
#define ENT_(name) z3::expr name
#define ENT(name) z3::expr name;
    X_x86_MEMS(ENT, ENT_);
#undef ENT
#undef ENT
    
    struct Sort {
      z3::func_decl cons;
      z3::sort sort;
      z3::func_decl_vector projs;

      enum class Fields {
	XM_LIST(X_x86_MEMS)
      };

      Sort(z3::context& ctx): cons(ctx), sort(ctx), projs(ctx) {
	constexpr std::size_t size = 3;
	const char *names[size] = { XM_STR_LIST(X_x86_MEMS) };
	const auto memsort = [&] (unsigned bytes) -> z3::sort {
	  return ctx.array_sort(ctx.bv_sort(32), ctx.bv_sort(bytes * 8));
	};
	const std::array<z3::sort, size> sorts = {memsort(1), memsort(2), memsort(4)};
	cons = ctx.tuple_sort("x86_mem", size, names, sorts.data(), projs);
	sort = cons.range();
      }

      MemState unpack(const z3::expr& e) const;
      z3::expr pack(MemState& mem) const;

    };

    MemState(z3::context& ctx, const Sort& sort);

    const z3::expr& mem(unsigned size) const;
    z3::expr& mem(unsigned size);

    z3::expr read(const z3::expr& address, unsigned size) const;
    void write(const z3::expr& address, const z3::expr& value);

    z3::context& ctx() const { return mem1.ctx(); }    
  };

  struct ArchState {
#define ENT_(name) z3::expr name
#define ENT(name) ENT_(name);
    X_x86_REGS(ENT, ENT_);
    X_x86_FLAGS(ENT, ENT_);
#undef ENT_
#undef ENT

    MemState mem;

    struct Sort;
    
    ArchState(z3::context& ctx, const Sort& sort);

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
    MemState::Sort mem;

    enum class Fields {
      XM_LIST(X_x86_REGS),
      XM_LIST(X_x86_FLAGS)
    };
    
    Sort(z3::context& ctx);
    
    ArchState unpack(const z3::expr& e) const;
    z3::expr pack(ArchState& arch) const;
  };

  struct Register {
    x86_reg reg;

    Register(x86_reg reg): reg(reg) {}

    z3::expr operator()(ArchState& arch) const;
    void operator()(ArchState& arch, const z3::expr& e) const;
  };

  struct MemoryOperand {
    const x86_op_mem& mem;

    MemoryOperand(const x86_op_mem& mem): mem(mem) {}

    z3::expr operator()(ArchState& arch, unsigned size) const;
    void operator()(ArchState& arch, const z3::expr& e) const;

    z3::expr address(ArchState& arch) const;
  };

  struct Operand {
    const cs_x86_op& op;

    Operand(const cs_x86_op& op): op(op) {}
    
    z3::expr operator()(ArchState& arch) const;
    void operator()(ArchState& arch, const z3::expr& e) const;

    unsigned size() const { return op.size; }
    unsigned bits() const { return size() * 8; }
  };

  struct Inst {
    cs_insn *I;
    cs_x86 *x86;

    Inst(cs_insn *I): I(I), x86(&I->detail->x86) {}
    
    void operator()(ArchState& arch) const { transfer(arch); }

    void transfer(ArchState& arch) const;

    bool has_multiple_exits() const {
      static const std::unordered_set<x86_insn> always_yes = {
	X86_INS_JAE,
	X86_INS_JA,
	X86_INS_JBE,
	X86_INS_JB,
	X86_INS_JCXZ,
	X86_INS_JECXZ,
	X86_INS_JE,
	X86_INS_JGE,
	X86_INS_JG,
	X86_INS_JLE,
	X86_INS_JL,
	X86_INS_JNE,
	X86_INS_JNO,
	X86_INS_JNP,
	X86_INS_JNS,
	X86_INS_JO,
	X86_INS_JP,
	X86_INS_JRCXZ,
	X86_INS_JS,
	X86_INS_RET,
      };
      if (always_yes.find(I->id) != always_yes.end()) {
	return true;
      }

      static const std::unordered_set<x86_insn> maybe_yes = {
	X86_INS_JMP,
	X86_INS_CALL,
      };
      if (maybe_yes.find(I->id) != maybe_yes.end()) {
	x86->operands[0].type
      }
      
      switch (I->id) {
      
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

    void transfer_acc_src(ArchState& arch) const;
    void transfer_acc_src_arith(ArchState& arch, z3::context& ctx, const z3::expr& acc,
				const z3::expr& src, unsigned bits, z3::expr& res) const;    
    void transfer_acc_src_logic(ArchState& arch, z3::context& ctx, const z3::expr& acc,
				const z3::expr& src, z3::expr& res) const;
    
  };

  using addr_t = uint32_t;

  struct Program {
    cs::handle handle {CS_ARCH_X86, CS_MODE_32};
    std::vector<cs::insns> insns;
    std::map<addr_t, Inst> map;
    using BasicBlock = std::vector<Inst>;
    std::map<addr_t, BasicBlock> blocks;

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

    void compute_basic_blocks();
  };

  struct CFG {
    using Rel = std::unordered_map<addr_t, std::unordered_set<addr_t>>;
    Rel fwd;
    Rel rev;

    void add_edge(addr_t src, addr_t dst) {
      fwd[src].insert(dst);
      fwd[dst].insert(src);
    }

    CFG(const Program& prog) {
      add_program(prog);
    }

    void add_program(const Program& prog) {
#if 0
      for (const auto& p : prog.map) {
	addr_t src = p.first;
	const auto *I = p.second.I;
	std::optional<addr_t> dst;
	switch (I->id) {
	case X86_INS_JMP: {
	  const auto& op = I->detail->x86.operands[0];
	  if (op.type == X86_OP_IMM) {
	    
	  }

	default: unimplemented("%s", I->mnemonic);
	}
	}
      }
#endif
    }
  };

  struct Context {
    z3::context ctx;

    ArchState::Sort arch_sort;
    MemState::Sort mem_sort;

    z3::expr archs;
    z3::expr path;
    const z3::expr idx;
    const z3::expr zero;

    unsigned next_id = 0;
    z3::expr constant(const z3::sort& sort) {
      return ctx.constant(std::to_string(next_id++).c_str(), sort);
    }

    ArchState unpack(const z3::expr& e) const { return arch_sort.unpack(e); }
    z3::expr pack(ArchState& t) const { return arch_sort.pack(t); }

    Context(): ctx(), arch_sort(ctx), mem_sort(ctx), archs(ctx), path(ctx), idx(ctx.int_const("idx")),
	       zero(ctx.int_val(0)) {
      archs = ctx.constant("archs", ctx.array_sort(ctx.int_sort(), arch_sort.sort));
      path = ctx.constant("path", ctx.array_sort(ctx.int_sort(), ctx.bv_sort(32)));

    }

    static constexpr int max = 16;

    z3::expr contains(const z3::expr& idx, int begin, int end) {
      return idx >= ctx.int_val(begin) && idx < ctx.int_val(end);
    }

    void constrain_init(z3::solver& solver) {
      solver.add(path[zero] == ctx.bv_val(0, 32), "init0");
      ArchState arch_zero {ctx, arch_sort};
      solver.add(archs[zero] == pack(arch_zero), "init1");
    }

    void constrain_path(z3::solver& solver) {
      ArchState arch = unpack(archs[idx]);
      const z3::expr next_pc = path[idx] == arch.eip;
      const z3::expr f = z3::forall(idx, z3::implies(contains(idx, 0, max), next_pc));
      solver.add(f, "path");
    }

    void constrain_transfer(z3::solver& solver, const Program& program) {
      const z3::expr arch_in = archs[idx];

      for (const auto& p : program.map) {
	const auto addr = p.first;
	const auto& inst = p.second;
	ArchState arch = unpack(arch_in);
	inst(arch);
	const z3::expr arch_out = pack(arch);
	const z3::expr transfer = z3::implies(path[idx] == ctx.bv_val(addr, 32),
					      archs[idx + 1] == arch_out);
	const z3::expr f = z3::forall(idx, z3::implies(contains(idx, 0, max), transfer));
	std::stringstream ss;
	ss << "transfer" << p.first;
	solver.add(f, ss.str().c_str());
      }
    }

    void constrain_pc(z3::solver& solver, const Program& program) {
      // TODO
    }

    void constrain(z3::solver& solver, const Program& program) {
      constrain_init(solver);
      constrain_path(solver);
      constrain_transfer(solver, program);
      constrain_pc(solver, program);

      solver.add(z3::exists(idx, contains(idx, 0, max) && unpack(archs[idx]).eax == 4));
    }


    void explore_paths(const Program& program) {
      z3::solver solver {ctx};
    }

    void explore_paths_rec(const Program& program, z3::solver& solver, addr_t addr) {
      // add instructions until branch
      
    }
    
  };

}
