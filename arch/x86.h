#pragma once

#include <map>
#include <array>
#include <unordered_map>
#include <unordered_set>

#define _XOPEN_SOURCE
#include <mach/i386/processor_info.h>
#include <mach/i386/_structs.h>
#include <i386/_mcontext.h>
#include <ucontext.h>
#include <mach/i386/thread_status.h>

#include <z3++.h>
#include <capstone/capstone.h>
#include "capstone++.h"

#include "xmacros.h"
#include "util.h"
#include "cores/macho.hh"

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
XB(cf, 0)					\
XB(zf, 6)					\
XE(sf, 7)

#define X_x86_MEMS(XB, XE)			\
XB(mem1)						\
XB(mem2)						\
XB(mem4)

struct MemState {
#define ENT_(name) z3::expr name
#define ENT(name) z3::expr name;
    X_x86_MEMS(ENT, ENT_);
#undef ENT
#undef ENT_
    
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
#define ENT_(name, ...) z3::expr name
#define ENT(name, ...) ENT_(name);
    X_x86_REGS(ENT, ENT_);
    X_x86_FLAGS(ENT, ENT_);
#undef ENT_
#undef ENT
    
    MemState mem;
    
    struct Sort;
    
    ArchState(z3::context& ctx, const Sort& sort);
    
    void create(unsigned id);
    
    z3::context& ctx() { return eax.ctx(); }
    
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
    }
    
    z3::expr operator==(const ArchState& other) const;
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
    
    void transfer_acc_src(ArchState& arch) const;
    void transfer_acc_src_arith(ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                const z3::expr& src, unsigned bits, z3::expr& res) const;
    void transfer_acc_src_logic(ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                const z3::expr& src, unsigned bits, z3::expr& res) const;
    void transfer_jcc(ArchState& arch, z3::context& ctx) const;
    void transfer_string(ArchState& arch, z3::context& ctx) const;
    
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
    
    std::size_t disasm(const uint8_t *data, std::size_t size, uint32_t address, std::size_t count = 0) {
        cs::insns new_insns;
        count = handle.disasm(data, size, address, count, new_insns);
        assert(new_insns.size() == count);
        for (cs_insn& new_insn : new_insns) {
            const Inst inst {&new_insn};
            map.emplace(new_insn.address, inst);
        }
        insns.push_back(std::move(new_insns));
        return count;
    }
    
    template <typename Container>
    std::size_t disasm(const Container& container, uint32_t address, std::size_t count = 0) {
        return disasm(container.data(), container.size() * sizeof(container.data()[0]), address, count);
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
    
    cores::MachOCore core;
    
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
    
    Context(const std::string& core_path): ctx(), core(core_path.c_str()), arch_sort(ctx), mem_sort(ctx), archs(ctx), path(ctx), idx(ctx.int_const("idx")),
    zero(ctx.int_val(0)) {
        archs = ctx.constant("archs", ctx.array_sort(ctx.int_sort(), arch_sort.sort));
        path = ctx.constant("path", ctx.array_sort(ctx.int_sort(), ctx.bv_sort(32)));
        core.parse();
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
    
    
    void explore_paths(Program& program) {
        z3::solver solver {ctx};
        ArchState in_arch {ctx, arch_sort};
        
        const cores::Thread& thd = core.thread(0);
        assert(thd.flavor == x86_THREAD_STATE32);
        
        x86_thread_state32_t state = * (const x86_thread_state32_t *) thd.data;
        
        std::cerr << "eip = " << std::hex << state.__eip << "\n";
        
#define ENT(name) in_arch.name = ctx.bv_val(state.__##name, 32);
        X_x86_REGS(ENT, ENT);
#undef ENT
#define ENT(name, bit) in_arch.name = ctx.bv_val((state.__eflags >> bit) & 1, 1);
        X_x86_FLAGS(ENT, ENT);
#undef ENT
        
        // set return address
        in_arch.mem.write(in_arch.esp, ctx.bv_val(0x42424242, 32));
        
        explore_paths_rec(program, in_arch, solver, state.__eip);
    }
    
    void explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr) {
        // add instructions until branch
        
        solver.push();
        {
            solver.add(ctx.bv_val(addr, 32) == in_arch.eip);
            
            if (program.map.find(addr) == program.map.end()) {
                // find address in core
                const auto seg_it = std::find_if(core.segments_begin(), core.segments_end(), [&] (const cores::Segment& seg) {
                    return seg.contains(addr, 1);
                });
                if (seg_it == core.segments_end()) {
                    std::cerr << "jump outside of address space: " << std::hex << addr << "\n";
                    goto done;
                }
                // TODO: make this safer
                const void *data = seg_it->at(addr);
                program.disasm((const uint8_t *) data, 16, addr, 1);
            }
            
            const Inst& inst = program.map.at(addr);
            
            ArchState arch = in_arch;
            inst.transfer(arch);
            ArchState out_arch = arch;
            out_arch.create(next_id++);
            solver.add(out_arch == arch);
            
            std::cerr << "inst @ " << std::hex << addr << " : "  << inst.I->mnemonic << " " << inst.I->op_str << "\n";
            
            while (true) {
                const auto res = solver.check();
                if (res != z3::sat) {
                    break;
                }
                const auto model = solver.get_model();
                const auto eip = model.eval(out_arch.eip);
                std::cerr << "eip = " << eip << "\n";
                
                explore_paths_rec(program, out_arch, solver, eip.as_int64());
                
                solver.add(out_arch.eip != eip);
            }
            
        }
    done:
        solver.pop();
    }
    
};

}
