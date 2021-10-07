#pragma once

#include <memory>
#include <vector>
#include <optional>

#include <z3++.h>

#include "cores/macho.hh"
#include "x86.h"
#include "memstate.h"
#include "program.h"
#include "peephole.h"
#include "cfg.h"

namespace x86 {

class ArchState;

struct Context {
    z3::context ctx;
    cores::MachOCore core;
    CoreProgram program;
    CFG cfg;
    
    std::vector<MemoryRange> symbolic_ranges;
    std::vector<std::unique_ptr<Peephole>> peepholes;
    std::vector<const cs_insn *> trace;
    
    ~Context() { std::cerr << "trace " << trace.size() << "\n"; }
    
    const z3::expr zero;
    
    const cs_insn *I;
    
    unsigned next_id = 0;
    z3::expr constant(const z3::sort& sort) {
        return ctx.constant(std::to_string(next_id++).c_str(), sort);
    }
    
    Context(const std::string& core_path): ctx(), core(core_path.c_str()), program(core), cfg(program), zero(ctx.int_val(0)) {
        core.parse();
        peepholes.push_back(std::make_unique<ReadEIP>());
    }
    
    static constexpr int max = 16;
    
    z3::expr contains(const z3::expr& idx, int begin, int end) {
        return idx >= ctx.int_val(begin) && idx < ctx.int_val(end);
    }
    
    using Read = MemState::Read;
    using Write = MemState::Write;
    using ReadVec = std::vector<Read>;
    using WriteVec = std::vector<Write>;
    
    struct Assignment {
        z3::expr pred;
        addr_t eip;
        ByteMap mask;
    };
    
    std::optional<Assignment> explore_paths_find_assigment(const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, ByteMap write_mask, const ReadVec& reads, const WriteVec& writes);
    
    void explore_paths_loop(const ArchState& in_arch, z3::solver& solver, const ByteMap& init_write_mask);
    
    void explore_paths();

    void explore_paths_rec_dst(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask);
    
    void explore_paths_rec_read(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const ReadVec& reads, const WriteVec& writes, ReadVec::const_iterator read_it);
    
    void explore_paths_rec_write(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const WriteVec& writes, WriteVec::const_iterator write_it);
    
    void explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr, ByteMap write_mask);
    
    void check_accesses(const ReadVec& reads, const WriteVec& writes, z3::solver& solver);
    void check_operands(const Inst& I, const ArchState& arch, z3::solver& solver);
    void check_regs(const ArchState& arch);
    
    std::optional<z3::model> find_execution(z3::solver& solver, const ReadVec& reads) const;
    
    template <typename OutputIt>
    OutputIt cover_execution(z3::solver& solver, const ReadVec& reads, OutputIt read_set_out) const;
    
    template <typename InputIt>
    void apply_read_set(z3::solver& solver, InputIt begin, InputIt end) const;
};

template <typename OutputIt>
OutputIt Context::cover_execution(z3::solver& solver, const ReadVec& reads, OutputIt read_set_out) const {
    z3::context& ctx = solver.ctx();
    const z3::expr mem = MemState::get_init_mem(ctx);
    std::unordered_set<addr_t> read_set;
    {
        z3::scope scope {solver};
        while (solver.check() == z3::sat) {
            const z3::eval eval {solver.get_model()};
            
            /* check if any new bytes were read */
            z3::expr binding = ctx.bool_val(true);
            for (const Read& read : reads) {
                binding = binding && read.addr == eval(read.addr);
                for (std::size_t i = 0; i < read.size(); ++i) {
                    const z3::expr addr = eval(read.addr + ctx.bv_val(static_cast<unsigned>(i), 32));
                    const uint32_t addr_ = addr.get_numeral_uint64();
                    if (read_set.insert(addr_).second) {
                        solver.add(mem[addr] == core.read<uint8_t>(addr_));
                    }
                }
            }
            
            // TODO: this might be exponenitally bad if there is a lot of flexibility in addresses...
            solver.add(!binding); // a different binding
        }
    }
    
    // add back read set (was removed in popped scope)
    for (addr_t addr : read_set) {
        z3::expr sym = ctx.bv_val((unsigned) addr, 32);
        solver.add(mem[sym] == core.read<uint8_t>(addr));
    }
    
    return std::copy(read_set.begin(), read_set.end(), read_set_out);
}

template <typename InputIt>
void Context::apply_read_set(z3::solver& solver, InputIt begin, InputIt end) const {
    z3::context& ctx = solver.ctx();
    const z3::expr mem = MemState::get_init_mem(ctx);
    for (auto it = begin; it != end; ++it) {
        const z3::expr addr = ctx.bv_val((unsigned) *it, 32);
        solver.add(mem[addr] == core.read<uint8_t>(*it));
    }
}

}
