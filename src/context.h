#pragma once

#include <memory>
#include <vector>
#include <optional>
#include <map>

#include <z3++.h>

#include "cores/macho.hh"
#include "x86.h"
#include "memstate.h"
#include "program.h"
#include "peephole.h"
#include "cfg.h"
#include "abstract.h"
#include "core.h"
#include "symbols.h"

namespace x86 {

class ArchState;

struct Symbols {
    using Map = std::map<uint64_t, std::string>;
    Map map;
    
    Symbols() {}
    
    void add(const struct core& core);
    
    const std::string *lookup(uint64_t vmaddr) const {
        const auto it = find(vmaddr);
        if (it == end()) {
            return nullptr;
        } else {
            return &it->second;
        }
    }
    
    Map::const_iterator end() const {
        return map.end();
    }
    
    Map::const_iterator find(uint64_t vmaddr) const {
        auto it = map.upper_bound(vmaddr);
        if (it == map.begin()) {
            return map.end();
        }
        --it;
        return it;
    }
    
    std::string desc(uint64_t vmaddr) const {
        const auto it = find(vmaddr);
        if (it == end()) {
            char buf[16];
            sprintf(buf, "%08llx", vmaddr);
            return buf;
        } else {
            std::stringstream ss;
            ss << it->second << "+" << (vmaddr - it->first);
            return ss.str();
        }
    }
};

struct Context {
    z3::context ctx;
    cores::MachOCore core;
    struct core core2;
    Symbols syms;
    CoreProgram program;
    CFG cfg;
    
    std::vector<MemoryRange> symbolic_ranges;
    std::vector<std::unique_ptr<Peephole>> peepholes;
    std::vector<const cs_insn *> trace;
    std::unordered_map<addr_t, transfer::transfer_function_t *> transfers;
    
    ~Context() { std::cerr << "trace " << trace.size() << "\n"; }
    
    const z3::expr zero;
    
    const cs_insn *I;
    
    unsigned next_id = 0;
    z3::expr constant(const z3::sort& sort) {
        return ctx.constant(std::to_string(next_id++).c_str(), sort);
    }
    
    Context(const std::string& core_path): ctx(), core(core_path.c_str()), program(core), cfg(program), zero(ctx.int_val(0)) {
        core.parse();
#if 0
        peepholes.push_back(std::make_unique<ReadEIP>());
#endif
        bind_abstract_transfers();
        if (core_fopen(core_path.c_str(), &core2) < 0) {
            core_perror("core_fopen");
            std::exit(EXIT_FAILURE);
        }
        syms.add(core2);
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
    
    void explore_paths_rec_read(Program& program, const ArchState& in_arch, ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const ReadVec& reads, const WriteVec& writes, ReadVec::const_iterator read_it);
    
    void explore_paths_rec_write(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const WriteVec& writes, WriteVec::const_iterator write_it);
    
    void explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr, ByteMap write_mask);
    void explore_paths_rec2(Program& program, const ArchState& in_arch, addr_t addr, z3::solver& solver, ByteMap initialized_mem);
    bool check_sat(const z3::expr_vector& preds, const ArchState& arch, z3::solver& solver, const ReadVec& reads, ByteMap& initialized_mem);
    bool check_sat(const z3::expr& pred, const ArchState& arch, z3::solver& solver, const ReadVec& reads, ByteMap& initialized_mem);
    template <class OutputIt>
    void find_assignments(const z3::expr& value, const ArchState& arch, z3::solver& solver, const ReadVec& reads, ByteMap& initialized_mem, OutputIt out);

    void check_accesses(const ReadVec& reads, const WriteVec& writes, z3::solver& solver);
    void check_operands(const Inst& I, ArchState& arch, z3::solver& solver);
    void check_regs(const ArchState& arch);
    
    unsigned trace_counter = 0;
    void dump_trace(const z3::model& model);
    
    std::optional<z3::model> find_execution(z3::solver& solver, const ReadVec& reads) const;
    
    template <typename OutputIt>
    OutputIt cover_execution(z3::solver& solver, const ReadVec& reads, OutputIt read_set_out) const;
    
    template <typename InputIt>
    void apply_read_set(z3::solver& solver, InputIt begin, InputIt end) const;
    
    void bind_abstract_transfers() {
#if 0
        transfers.emplace(0xa7c5c279, transfer::sym_strncat);
        transfers.emplace(0xa7de7e09, transfer::sym_strnlen);
        transfers.emplace(0xa7ca0a18, transfer::sym_strncasecmp);
#endif
    }
};

#if 0
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
#endif

}
