#pragma once

#include <set>
#include <vector>
#include <optional>

#include "x86.h"
#include "inst.h"
#include "program.h"

namespace x86 {

struct Context;

class CFG {
public:
    using Map = AddrMap;
    Map fwd, rev;
    
    void add(addr_t addr);
    
    struct Loop;
    
    template <typename OutputIt>
    OutputIt get_loops(addr_t entry, OutputIt out) const;
    
    CFG(CoreProgram& program): program(program) {}
    
private:
    CoreProgram& program;
    AddrSet seen;
    
    template <typename OutputIt>
    OutputIt get_successors(addr_t addr, const cs_insn& I, OutputIt out) const;
    
    void add_edge(addr_t src, addr_t dst) {
        fwd[src].insert(dst);
        rev[dst].insert(src);
    }
    
    template <typename OutputIt>
    void get_loops_rec(addr_t addr, Loop& loop, AddrSet& seen, OutputIt& out) const;
};

struct CFG::Loop {
    std::vector<Inst> body;
    std::set<Inst> exits;
    
    void transfer(ArchState& arch, ReadOut read_out, WriteOut write_out) const;
    
    std::optional<ArchState> analyze(const ArchState& in, z3::solver& solver, const Context& context);
    
    uint64_t entry_addr() const {
        return body.front().I->address;
    }
    
    struct Analysis;
    
private:
    using ReadVec = std::vector<MemState::Read>;
    using WriteVec = std::vector<MemState::Write>;

    struct Iteration;
    struct Step;
    
    void transfer_iteration(Iteration& iter, bool reset_mem = false) const;
    
    template <typename OutputIt>
    OutputIt writes(const z3::expr& begin, const z3::expr& end, OutputIt out) const;
    
    std::string name(const std::string& s) const {
        std::stringstream ss;
        ss << s << std::hex << body.front().I->address;
        return ss.str();
    }
    
    z3::expr constant(const std::string& s, const z3::sort& sort) const {
        return sort.ctx().constant(name(s).c_str(), sort);
    }
    
};


struct CFG::Loop::Iteration {
    std::vector<ArchState> archs; // n+1
    std::vector<ReadVec> reads; // n
    std::vector<WriteVec> writes; // n
    
    Step step(std::size_t idx) const;
    std::vector<MemState::Access> accesses() const;
    void clear() {
        archs.clear();
        reads.clear();
        writes.clear();
    }

    void transform_exprs(std::function<z3::expr (const z3::expr&)> f);
    void substitute(const z3::expr_vector& src, const z3::expr_vector& dst);
    
    ReadVec get_reads() const {
        ReadVec res;
        for (const auto& rds : reads) {
            for (const auto& rd : rds) {
                res.push_back(rd);
            }
        }
        return res;
    }
    
    WriteVec get_writes() const {
        WriteVec res;
        for (const auto& wrs : writes) {
            for (const auto& wr : wrs) {
                res.push_back(wr);
            }
        }
        return res;
    }
    
    Iteration() {}
    Iteration(const ArchState& in) { archs.push_back(in); }
};


struct CFG::Loop::Analysis {
    /* inputs */
    const Loop& loop;
    const ArchState& in;
    z3::solver& solver;
    const Context& context;
    
    /* outputs */
    std::vector<Iteration> iters;
    std::unordered_set<addr_t> read_set;
    ArchState out_param;

    std::optional<ArchState> analyze();
    
    Analysis(const Loop& loop, const ArchState& in, z3::solver& solver, const Context& context): loop(loop), in(in), solver(solver), context(context), out_param(in.ctx()), idx(ctx()), sym_in(ctx()), sym_out_param(ctx()) {
        sym_in.symbolic();
        idx = ctx().bv_const("idx", 32);
    }
    
private:
    z3::context& ctx() const { return in.ctx(); }
    void set_iters_1(); // sets `iters`, `read_set`.
    void check_aliases_2();
    void find_access_strides_3();
    void set_out_param_4();
    
    /* test_reg is concrete except for idx. */
    bool check_arch_state_reg(z3::expr ArchState::*reg, const z3::expr& test_reg);
    
    z3::expr idx;
    ArchState sym_in, sym_out_param;
    const ArchState& sym_out() const {
        return sym_iter().archs.back();
    }
    std::vector<Iteration> sym_iters;
    const Iteration& sym_iter() const {
        return sym_iters.front();
    }
    std::vector<z3::expr ArchState::*> seq_regs, comb_regs, const_regs;
    bool check_constant_reg(z3::expr ArchState::*reg);
    bool check_sequential_reg(z3::expr ArchState::*reg);
    void check_combinatorial_reg(z3::expr ArchState::*reg);
    
    struct exception {
        std::string reason;
        exception(const std::string& reason): reason(reason) {}
    };
    
};

template <typename OutputIt>
OutputIt CFG::get_loops(addr_t entry, OutputIt out) const {
    AddrSet seen;
    Loop loop;
    get_loops_rec(entry, loop, seen, out);
    return out;
}

template <typename OutputIt>
void CFG::get_loops_rec(addr_t addr, Loop& loop, AddrSet& seen, OutputIt& out) const {
    // base case: found loop
    if (!loop.body.empty() && loop.body[0].I->address == addr) {
        *out++ = loop;
        return;
    }
    
    // base case: internal loop
    if (!seen.insert(addr).second) {
        return;
    }
    
    // recursive case
    const Inst& I = program.at(addr);
    loop.body.push_back(I);
    const auto& succs = fwd.at(addr);
    if (succs.size() > 1) {
        loop.exits.insert(I);
    }
    
    for (addr_t succ : succs) {
        get_loops_rec(succ, loop, seen, out);
    }
    
    loop.exits.erase(I);
    loop.body.pop_back();
    seen.erase(addr);
}

}
