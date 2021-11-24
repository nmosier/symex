#include <gperftools/profiler.h>

#include "x86.h"
#include "program.h"
#include "context.h"
#include "util.h"
#include "peephole.h"

namespace x86 {

void Context::explore_paths_loop(const ArchState& init_arch, z3::solver& solver, const ByteMap& init_write_mask) {
    struct Entry {
        ArchState in, out;
        ByteMap mask;
        ReadVec reads;
        WriteVec writes;
        z3::expr pred;
    };
    
    std::vector<Entry> stack = {
        {.in = init_arch, .out = init_arch, .mask = init_write_mask, .reads = {}, .writes = {}, .pred = ctx.bool_val(true)}
    };
    solver.push();
    
    unsigned trace_id = 0;
    trace.push_back(program.disasm(init_arch.eip.get_numeral_uint64())->I);
    
    while (!stack.empty()) {
        
        const Entry& entry = stack.back();
        
        /* perform checks */
        // memory access addresses only have 1 possibility
        check_accesses(entry.reads, entry.writes, solver);
        check_regs(entry.out);
        
        const std::optional<Assignment> assignment = explore_paths_find_assigment(entry.in, entry.out, solver, entry.mask, entry.reads, entry.writes);
        
        
        if (assignment) {
            solver.push();
            solver.add(assignment->pred);
            const addr_t addr = assignment->eip;
            
            ReadVec reads;
            WriteVec writes;
            const auto read_out = std::back_inserter(reads);
            const auto write_out = std::back_inserter(writes);
            
            const Inst *inst = program.disasm(addr);
            if (inst == nullptr) {
                std::cerr << "jump outside of address space: " << std::hex << addr << "\n";
                std::stringstream ss;
                ss << "trace" << trace_id++ << ".asm";
                dump_trace(ss.str(), trace);
                solver.pop();
                solver.add(!assignment->pred);
                // stack.pop_back();
                continue;
            }
            
            // add to CFG
            cfg.add(addr);
            
            // print loop
            if (addr == 0xa7de9cb4) {
                if (solver.check() == z3::sat) {
                    entry.out.stackdump(16, z3::eval {solver.get_model()});
                }
            }
            
            // DEBUG: get & print loops
            std::optional<ArchState> loop_out;
            {
                std::vector<CFG::Loop> loops;
                cfg.get_loops(addr, std::back_inserter(loops));
                for (auto& loop : loops) {
#if 0
                    CFG::Loop::Analysis analysis(loop, entry.out, solver, *this);
                    loop_out = analysis.analyze();
#elif 1
                    CFG::Loop::Analysis2 analysis(loop, ctx);
                    analysis.run();
#else
                    loop_out = loop.analyze(entry.out, solver, *this);
#endif
                }
            }
            
            // DEBUG: function transfers
            const auto transfers_it = transfers.find(addr);
            if (transfers_it != transfers.end()) {
                ArchState arch = entry.out;
                transfers_it->second(arch, solver);
                loop_out = arch;
                std::cerr << "HERE\n";
            }
            
            trace.push_back(inst->I);
            
            ArchState out_arch {ctx};
            
            if (loop_out) {
                std::cerr << "LOOP FOUND\n";
                out_arch = *loop_out;
            } else {
                
                const ArchState& in_arch = entry.out;
                ArchState arch = in_arch;
                arch.eip = ctx.bv_val(assignment->eip, 32);
                arch.simplify();
                
                bool match = false;
                for (const auto& peephole : peepholes) {
                    if ((*peephole)(addr, program, arch, read_out, write_out)) {
                        match = true;
                        break;
                    }
                }
                
                if (!match) {
                    inst->transfer(arch, read_out, write_out);
                }
                
                out_arch = arch;
                out_arch.create(next_id++, solver);
                
                std::cerr << "inst @ " << std::hex << addr << " : "  << inst->I->mnemonic << " " << inst->I->op_str << "\n";
                I = inst->I;
                
            }
            
            // check_operands(*inst, out_arch, solver);
            
            stack.push_back({.in = entry.out, .out = out_arch, .mask = assignment->mask, .reads = reads, .writes = writes, .pred = assignment->pred});
            
        } else {
            solver.pop();
            solver.add(!entry.pred);
            stack.pop_back();
            trace.pop_back();
        }
    }
    
    // solver.pop();
}

void Context::explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr, ByteMap write_mask) {
    // add instructions until branch
    
    if (program.map.find(addr) == program.map.end()) {
        // find address in core
        const auto seg_it = std::find_if(core.segments_begin(), core.segments_end(), [&] (const cores::Segment& seg) {
            return seg.contains(addr, 1);
        });
        if (seg_it == core.segments_end()) {
            std::cerr << "jump outside of address space: " << std::hex << addr << "\n";
            dump_trace("trace.asm", trace);
            return;
        }
        // TODO: make this safer
        const void *data = seg_it->at(addr);
        program.disasm((const uint8_t *) data, 16, addr, 1);
    }
    
    const Inst& inst = program.map.at(addr);
    
    trace.push_back(inst.I);
    
    ArchState arch = in_arch;
    ReadVec reads;
    WriteVec writes;
    inst.transfer(arch, std::back_inserter(reads), std::back_inserter(writes));
    ArchState out_arch = arch;
    out_arch.create(next_id++, solver);
    
    if (writes.size() == 0) {
        assert(z3::eq(out_arch.mem.mem, in_arch.mem.mem));
    }
    
    std::cerr << "inst @ " << std::hex << addr << " : "  << inst.I->mnemonic << " " << inst.I->op_str << "\n";
    
    I = inst.I;
    
    explore_paths_rec_read(program, in_arch, out_arch, solver, write_mask, reads, writes, reads.begin());
    
    trace.pop_back();
}

void Context::explore_paths() {
    z3::solver solver {ctx};
    ArchState in_arch {ctx};
    
    // DEBUG: profiler
    ProfilerStart("a.prof");
    ::signal(SIGINT, [] (int sig) {
        ProfilerStop();
        std::exit(0);
    });
    std::atexit(ProfilerStop);
    
    
    const cores::Thread& thd = core.thread(0);
    assert(thd.flavor == x86_THREAD_STATE32);
    
    x86_thread_state32_t state = * (const x86_thread_state32_t *) thd.data;
    
    std::cerr << "eip = " << std::hex << state.__eip << "\n";
    
#define ENT(name, bits) in_arch.name = ctx.bv_val(state.__##name, 32);
    X_x86_REGS(ENT, ENT);
#undef ENT
#define ENT(name, bits, bit) in_arch.name = ctx.bv_val((state.__eflags >> bit) & 1, 1);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
    
    // TODO: restore xmms too
    
    ByteMap write_mask;
    for (const auto& range : symbolic_ranges) {
        for (uint64_t addr = range.base; addr < range.base + range.len; ++addr) {
            write_mask.insert(addr);
        }
    }
    
    // set return address
    in_arch.mem.write(in_arch.esp, ctx.bv_val(0x42424242, 32), util::null_output_iterator());
    for (uint64_t i = 0; i < 4; ++i) {
        write_mask.insert(in_arch.esp.get_numeral_uint64() + i);
    }
    
    auto e = in_arch.mem.read(in_arch.esp, 4, util::null_output_iterator());
    solver.push();
    solver.add(e != 0x42424242);
    assert(solver.check() == z3::unsat);
    solver.pop();
 
#if 0
    explore_paths_loop(in_arch, solver, write_mask);
#elif 0
    explore_paths_rec(program.program, in_arch, solver, in_arch.eip.get_numeral_uint64(), write_mask);
#else
    explore_paths_rec2(program.program, in_arch, in_arch.eip.get_numeral_uint64(), solver, write_mask, ReadVec());
#endif
}


std::optional<Context::Assignment> Context::explore_paths_find_assigment(const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, ByteMap write_mask, const ReadVec& reads, const WriteVec& writes) {
    
    z3::scope scope {solver};
    
    z3::model model {ctx};
    const auto recheck = [&] {
        const z3::check_result res = solver.check();
        if (res != z3::sat) {
            return false;
        } else {
            model = solver.get_model();
            return true;
        }
    };
    
#define recheck() if (!(recheck)()) { return std::nullopt; }
    
    recheck();
    
    z3::expr acc = ctx.bool_val(true);
    const auto add = [&] (const z3::expr& e) {
        acc = acc && e;
    };
    
    // concretize reads
    for (const Read& sym_read : reads) {
        // TODO: clean this code/API up
        Read con_read = sym_read.eval(model);
        con_read.data = sym_read.data;
        con_read.data = con_read(core, write_mask);
        add(con_read == sym_read);
        solver.add(con_read == sym_read);
    }

    recheck();
    
    // concretize writes
    for (const Write& sym_write : writes) {
        Write con_write = sym_write.eval(model);
        add(sym_write.addr == con_write.addr);
        for (unsigned i = 0; i < con_write.size(); ++i) {
            write_mask.insert(con_write.addr.get_numeral_uint64() + i);
        }
    }
    
    // concretize dst
    add(out_arch.eip == model.eval(out_arch.eip));
    
#if 0
    // DEBUG: check for multiple dsts
    {
        z3::scope scope {solver};
        solver.add(out_arch.eip != model.eval(out_arch.eip));
        if (solver.check() == z3::sat) {
            std::cerr << "DSTS: " << in_arch.eip.simplify() << "\n";
            // std::abort();
        }
        
    }
#endif
    
    return Assignment {.pred = acc, .eip = static_cast<addr_t>(model.eval(out_arch.eip).get_numeral_uint64()), .mask = write_mask};
#undef recheck
}

void Context::explore_paths_rec_dst(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask) {
    unsigned count = 0;
    while (true) {
        const z3::check_result res = solver.check();
        if (res != z3::sat) {
            const auto core = solver.unsat_core();
            for (const auto& e : core) {
                std::cerr << e << "\n";
            }
            break;
        }
        if (count > 0) {
            std::cerr << "error: nondeterministic\n";
            std::abort();
        }
        const z3::model model = solver.get_model();
        const z3::expr eip = model.eval(out_arch.eip);
        std::cerr << "dst " << eip << "\n";
         
        solver.push();
        {
            solver.add(eip == out_arch.eip);
            explore_paths_rec(program, out_arch, solver, eip.get_numeral_uint64(), write_mask);
        }
        solver.pop();
        solver.add(eip != out_arch.eip);
        ++count;
    }
}

void Context::explore_paths_rec_read(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const ReadVec& reads, const WriteVec& writes, ReadVec::const_iterator read_it) {
    
    if (read_it == reads.end()) {
        explore_paths_rec_write(program, in_arch, out_arch, solver, write_mask, writes, writes.begin());
        return;
    }
    
    const auto& sym_read = *read_it;
    
    // DEBUG: check for misaligned reads
    solver.push();
    {
        const z3::expr mask = ctx.bv_val((unsigned) sym_read.size() - 1, 32);
        solver.add((sym_read.addr & mask) != 0);
        const auto res = solver.check();
        assert(res == z3::unsat);
    }
    solver.pop();
    
    unsigned count = 0;
    while (true) {
        const z3::check_result res = solver.check();
        if (res != z3::sat) {
            break;
        }
        if (count > 0) {
            std::cerr << "error: nondeterministic\n";
            std::abort();
        }
        const z3::model model = solver.get_model();

        MemState::Read con_read = sym_read.eval(model);
        const auto olddata = con_read.data;
        con_read.data = sym_read.data; // NOTE: this fixes bug maybe?
        con_read.data = con_read(core, write_mask);
        
        std::cerr << "read " << con_read.addr << " " << model.eval(con_read.data) << " (" << olddata << ")\n";
        
        solver.push();
        {
            solver.add(con_read == sym_read);
            explore_paths_rec_read(program, in_arch, out_arch, solver, write_mask, reads, writes, std::next(read_it));
        }
        solver.pop();
        solver.add(con_read.addr != sym_read.addr);
        ++count;
    }
}

void Context::explore_paths_rec_write(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const WriteVec& writes, WriteVec::const_iterator write_it) {
    if (write_it == writes.end()) {
        explore_paths_rec_dst(program, in_arch, out_arch, solver, write_mask);
        return;
    }
    
    const auto& sym_write = *write_it;
    
    // DEBUG: check for misaligned writes
#if 0
    solver.push();
    {
        const z3::expr mask = ctx.bv_val((unsigned) sym_write.size() - 1, 32);
        solver.add((sym_write.addr & mask) != 0);
        const auto res = solver.check();
        assert(res == z3::unsat);
    }
    solver.pop();
#endif
    
    unsigned count = 0;
    while (true) {
        const z3::check_result res = solver.check();
        if (res != z3::sat) {
            break;
        }
        if (count > 0) {
            std::cerr << "error: nondeterministic\n";
            std::abort();
        }
        const z3::model model = solver.get_model();
        MemState::Write con_write = sym_write.eval(model);
        std::cerr << "write " << con_write.addr << " " << con_write.data << "\n";
        
        solver.push();
        {
            solver.add(con_write.addr == sym_write.addr);
            ByteMap new_write_mask = write_mask;
            for (std::size_t i = 0; i < sym_write.size(); ++i) {
                new_write_mask.insert(con_write.addr.get_numeral_uint64() + i);
            }
            explore_paths_rec_write(program, in_arch, out_arch, solver, new_write_mask, writes, std::next(write_it));
        }
        solver.pop();
        
        solver.add(sym_write.addr != con_write.addr);
        ++count;
    }
}




void Context::explore_paths_rec2(Program& program, const ArchState& arch_in, addr_t addr, z3::solver& solver, ByteMap initialized_mem, ReadVec reads) {
    
    /* add new control-flow path to the CFG */
    if (!program.map.contains(addr)) {
        /* find executable segment */
        const auto seg_it = std::find_if(core.segments_begin(), core.segments_end(), [&] (const cores::Segment& seg) {
            return seg.contains(addr, 1);
        });
        if (seg_it == core.segments_end()) {
            std::cerr << "jump outside of address space: " << std::hex << addr << "\n";
            dump_trace("trace.asm", trace);
            return;
        }
        const void *data = seg_it->at(addr);
        // TODO: shouldn't pass 16; need to pass  correct value
        program.disasm(static_cast<const uint8_t *>(data), 16, addr, 1);
    }
    
    const Inst& inst = program.map.at(addr);
    
    trace.push_back(inst.I);
    
    ArchState arch = arch_in;
    WriteVec writes;
    inst.transfer(arch, std::back_inserter(reads), std::back_inserter(writes));
    ArchState arch_out = arch;
    
    std::cerr << "inst @ " << std::hex << addr << " : " << inst.I->mnemonic << " " << inst.I->op_str << "\n";
    
    I = inst.I;
    
    /* find possible successors */
    std::vector<z3::expr> out_eips;
    find_assignments(arch_out.eip, arch_out, solver, reads, initialized_mem, std::back_inserter(out_eips));
    
    std::cerr << out_eips.size() << " successors\n";
    
    for (const z3::expr& out_eip : out_eips) {
        z3::scope scope {solver};
        solver.add(arch_out.eip == out_eip);
        explore_paths_rec2(program, arch_out, out_eip.get_numeral_uint64(), solver, initialized_mem, reads);
    }
    
    trace.pop_back();
}

bool Context::check_sat(const z3::expr& pred, const ArchState& arch, z3::solver& solver, const ReadVec& reads, ByteMap& initialized_mem) {
    z3::expr_vector v(ctx);
    v.push_back(pred);
    return check_sat(v, arch, solver, reads, initialized_mem);
}

template <class OutputIt>
void Context::find_assignments(const z3::expr& sym_value, const ArchState& arch, z3::solver& solver, const ReadVec& reads, ByteMap& initialized_mem, OutputIt out) {
    
    z3::expr_vector inequalities(ctx);
    
    while (check_sat(inequalities, arch, solver, reads, initialized_mem)) {
        const z3::model model = solver.get_model();
        const z3::expr con_value = model.eval(sym_value, true);
        inequalities.push_back(sym_value != con_value);
        *out++ = con_value;
    }
}

// TODO: really, this should accept an access vec so it can avoid asserting redundant reads.
bool Context::check_sat(const z3::expr_vector& preds, const ArchState& arch, z3::solver& solver, const ReadVec& reads, ByteMap& initialized_mem) {
    /* Iterative approach:
     * 1. Check if predicate is satisfiable given current constraints.
     *    (a) If so, check all reads under model.
     *    (b) If any reads haven't been initialized, initialize in constraints and then go to 1.
     * 2. Done
     */
    
    const auto init_mem = MemState::get_init_mem(ctx);
    
    while (true) {
        const auto res = solver.check(preds);
        switch (res) {
            case z3::sat:
                break;
                
            case z3::unsat:
                return false;
                
            case z3::unknown:
                std::cerr << "unknown check() result\n";
                std::abort();
                
            default: std::abort();
        }
        
        const z3::model model = solver.get_model();
        
        bool changed = false;
        for (const Read& read : reads) {
            for (std::size_t i = 0; i < read.size(); ++i) {
                const z3::expr sym_addr = model.eval(read.addr + ctx.bv_val(static_cast<uint64_t>(i), 32), true);
                const addr_t con_addr = sym_addr.get_numeral_uint64();
                if (initialized_mem.insert(con_addr).second) {
                    if (const auto data = core.try_read<uint8_t>(con_addr)) {
                        solver.add(init_mem[sym_addr] == *data, util::to_string("init read ", sym_addr).c_str());
                        changed = true;
                    } else {
                        /* bad read: not in address space
                         * Often, this is OK because of underconstrained read results? Actually, no.
                         */
                        if (changed) {
                            break;
                        } else {
                            std::cerr << "bad read: outside of address space\n";
                            std::abort();
                        }
                    }
                }
            }
        }
        if (!changed) {
            return true;
        }
    }
}


std::optional<z3::model> Context::find_execution(z3::solver& solver, const ReadVec& reads) const {
    z3::context& ctx = solver.ctx();
    const z3::expr mem = MemState::get_init_mem(ctx);
    std::unordered_set<addr_t> read_set;
    while (true) {
        /* check whether any execution exists */
        if (solver.check() != z3::sat) {
            return std::nullopt;
        }
        const z3::eval eval {solver.get_model()};
        
        /* check if any new bytes were read */
        // TODO: This can be optimized by also looking at written bytes. Also by knowing previous read set.
        bool change = false;
        for (const Read& read : reads) {
            for (std::size_t i = 0; i < read.size(); ++i) {
                const z3::expr addr = eval(read.addr + ctx.bv_val(static_cast<unsigned>(i), 32));
                const uint32_t addr_ = addr.get_numeral_uint64();
                if (read_set.insert(addr_).second) {
                    std::stringstream ss;
                    static unsigned junk = 0;
                    ss << "init-" << addr << "-" << junk++;
                    solver.add(mem[addr] == core.read<uint8_t>(addr_), ss.str().c_str());
                    change = true;
                }
            }
        }
        if (!change) {
            break;
        }
    }
    
    return solver.get_model();
}



}
