#pragma once

#include <memory>
#include <vector>
#include <z3++.h>
#include "cores/macho.hh"
#include "x86.h"
#include "memstate.h"
#include "program.h"
#include "peephole.h"

namespace x86 {

class ArchState;

struct Context {
    z3::context ctx;
    cores::MachOCore core;
    CoreProgram program;
    
    std::vector<MemoryRange> symbolic_ranges;
    std::vector<std::unique_ptr<Peephole>> peepholes;
    std::vector<const cs_insn *> trace;
    
    const z3::expr zero;
    
    const cs_insn *I;
    
    unsigned next_id = 0;
    z3::expr constant(const z3::sort& sort) {
        return ctx.constant(std::to_string(next_id++).c_str(), sort);
    }
    
    Context(const std::string& core_path): ctx(), core(core_path.c_str()),
    program(core), zero(ctx.int_val(0)) {
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
};

}
