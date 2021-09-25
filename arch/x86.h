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
XB(sf, 7) \
XE(of, 11)

#define X_x86_MEMS(XB, XE)			\
XB(mem1)						\
XB(mem2)						\
XB(mem4)

using addr_t = uint32_t;
using ByteMap = std::unordered_set<addr_t>;

struct MemState {
    z3::context& ctx;
    z3::expr mem;
    
    struct Access {
        z3::expr addr;
        z3::expr data;
        
        Access eval(const z3::model& model) const {
            return Access {model.eval(addr), model.eval(data)};
        }
        
        z3::context& ctx() const { return addr.ctx(); }
        unsigned bits() const { return data.get_sort().bv_size(); }
        std::size_t size() const { return bits() / 8; }
        
        z3::expr operator==(const Access& other) const {
            return addr == other.addr && data == other.data;
        }
        
        z3::expr operator!=(const Access& other) const {
            return !(*this == other);
        }
    };
    
    struct Read: Access {
        Read eval(const z3::model& model) const { return Read {Access::eval(model)}; }
        
        uint64_t operator()(const cores::Core& core) const {
            const uint64_t addr = this->addr.as_uint64();
            switch (this->data.get_sort().bv_size() / 8) {
                case 1: return core.read<uint8_t>(addr);
                case 2: return core.read<uint16_t>(addr);
                case 4: return core.read<uint32_t>(addr);
                default: std::abort();
            }
        }
        
        z3::expr operator()(const cores::Core& core, const ByteMap& write_mask) const {
            uint64_t addr = this->addr.as_uint64();
            z3::expr data = this->data;
            std::vector<z3::expr> res;
            for (unsigned i = 0; i < size(); ++i) {
                z3::expr byte {ctx()};
                if (write_mask.find(addr + i) == write_mask.end()) {
                    byte = ctx().bv_val(core.read<uint8_t>(addr + i), 8);
                } else {
                    byte = data.extract((i + 1) * 8 - 1, i * 8);
                }
                res.push_back(byte);
            }
            return z3::concat(res.rbegin(), res.rend());
        }
    };
    
    struct Write: Access {
        Write eval(const z3::model& model) const { return Write {Access::eval(model)}; }
    };
    
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

    template <typename OutputIt>
    z3::expr read(const z3::expr& address, unsigned size, OutputIt read_out) const;
    
    template <typename OutputIt>
    void write(const z3::expr& address, const z3::expr& value, OutputIt write_out);
    
private:
    z3::expr read_aligned(const z3::expr& addr_hi, const z3::expr& addr_lo, unsigned size) const;
    z3::expr read_unaligned(const z3::expr& addr_hi, const z3::expr& addr_lo, unsigned size) const;
};

struct ArchState {
#define ENT_(name, ...) z3::expr name
#define ENT(name, ...) ENT_(name);
    X_x86_REGS(ENT, ENT_);
    X_x86_FLAGS(ENT, ENT_);
#undef ENT_
#undef ENT
    static constexpr std::size_t nxmms = 8;
    static constexpr unsigned xmm_bits = 128;
    std::vector<z3::expr> xmms;
    
    MemState mem;
    
    struct Sort;
    
    ArchState(z3::context& ctx, const Sort& sort);
    
    void create(unsigned id, z3::solver& solver);
    
    z3::context& ctx() const { return eax.ctx(); }
    
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
        for (z3::expr& xmm : xmms) {
            xmm = ctx().bv_val(0, xmm_bits);
        }
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
    
    z3::expr read(const ArchState& arch) const;
    void write(ArchState& arch, const z3::expr& e) const;
};

struct MemoryOperand {
    const x86_op_mem& mem;
    
    MemoryOperand(const x86_op_mem& mem): mem(mem) {}
    
    template <typename OutputIt>
    z3::expr read(const ArchState& arch, unsigned size, OutputIt read_out) const;
    
    template <typename OutputIt>
    void write(ArchState& arch, const z3::expr& e, OutputIt write_out) const;
    
    z3::expr addr(const ArchState& arch) const;
};

struct Operand {
    const cs_x86_op& op;
    
    Operand(const cs_x86_op& op): op(op) {}
    
    template <typename OutputIt>
    z3::expr read(const ArchState& arch, OutputIt read_out) const;
    
    template <typename OutputIt>
    void write(ArchState& arch, const z3::expr& e, OutputIt write_out) const;
    
    unsigned size() const { return op.size; }
    unsigned bits() const { return size() * 8; }
};

struct Inst {
    cs_insn *I;
    cs_x86 *x86;
    
    Inst(cs_insn *I): I(I), x86(&I->detail->x86) {}
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer(ArchState& arch, OutputIt1 read_out, OutputIt2 write_out) const;
    
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
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer_acc_src(ArchState& arch, OutputIt1 read_out, OutputIt2 write_out) const;
    
    z3::expr transfer_acc_src_arith(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                const z3::expr& src, unsigned bits) const;
    z3::expr transfer_acc_src_logic(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                const z3::expr& src, unsigned bits) const;
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer_jcc(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const;
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer_cmovcc(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const;
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer_string(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const;
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer_string_rep(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const;
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer_shift(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const;
    
    template <typename OutputIt1, typename OutputIt2>
    void transfer_imul(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const;
};


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

    } kind;
    
    Condition(Kind kind): kind(kind) {}
    
    const char *str() const {
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
            default: unimplemented("cc %d", kind);
        }
    }
    
    z3::expr operator()(const ArchState& arch) const {
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
            default: unimplemented("cc %s", str());
        }
    }
};

struct MemoryRange {
    uint64_t base;
    uint64_t len;
};

struct Context {
    z3::context ctx;
    
    cores::MachOCore core;
    
    ArchState::Sort arch_sort;
    MemState::Sort mem_sort;
    
    std::vector<MemoryRange> symbolic_ranges;
    std::vector<const cs_insn *> trace;
    
    z3::expr archs;
    z3::expr path;
    const z3::expr idx;
    const z3::expr zero;
    
    const cs_insn *I;
    
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
    
#if 0
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
#endif
    
    using Read = MemState::Read;
    using Write = MemState::Write;
    using ReadVec = std::vector<Read>;
    using WriteVec = std::vector<Write>;
    
    struct Assignment {
        z3::expr pred;
        addr_t eip;
        ByteMap mask;
    };
    
    std::optional<Assignment> explore_paths_find_assigment(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, ByteMap write_mask, const ReadVec& reads, const WriteVec& writes);
    
    void explore_paths_loop(Program& program, const ArchState& in_arch, z3::solver& solver, const ByteMap& init_write_mask);
    
    void explore_paths(Program& program);

    void explore_paths_rec_dst(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask);
    
    void explore_paths_rec_read(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const ReadVec& reads, const WriteVec& writes, ReadVec::const_iterator read_it);
    
    void explore_paths_rec_write(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const WriteVec& writes, WriteVec::const_iterator write_it);
    
    void explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr, ByteMap write_mask);
    
    void check_accesses(const ReadVec& reads, const WriteVec& writes, z3::solver& solver);
};

std::ostream& dump_trace(std::ostream& os, const std::vector<const cs_insn *>& trace);
void dump_trace(const std::string& path, const std::vector<const cs_insn *>& trace);

}
