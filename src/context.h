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
    
    ~Context() { std::cerr << "Traces: " << trace_counter << "\n"; }
    
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
    
    void explore_paths();
    void explore_paths_rec_dst(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver);
    void explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr);

    void check_accesses(const ReadVec& reads, const WriteVec& writes, z3::solver& solver);
    void check_operands(const Inst& I, ArchState& arch, z3::solver& solver);
    void check_regs(const ArchState& arch);
    
    unsigned trace_counter = 0;
    void dump_trace(const z3::model& model, const ArchState& arch, const std::string& reason);
    
    void bind_abstract_transfers() {
#if 0
        transfers.emplace(0xa7c5c279, transfer::sym_strncat);
        transfers.emplace(0xa7de7e09, transfer::sym_strnlen);
        transfers.emplace(0xa7ca0a18, transfer::sym_strncasecmp);
#endif
    }
};


}
