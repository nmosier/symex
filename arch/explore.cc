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

            // DEBUG: get & print loops
            std::optional<ArchState> loop_out;
            {
                std::vector<CFG::Loop> loops;
                cfg.get_loops(addr, std::back_inserter(loops));
                for (auto& loop : loops) {
#if 0
                    if (const auto loop_out_ = loop.analyze(entry.out, solver, reads, writes)) {
                        loop_out = loop_out_;
                        break;
                    }
#else
                    loop_out = loop.analyze2(entry.out, solver, *this);
#endif
                }
            }
            
            ArchState out_arch {ctx};
            
            if (loop_out) {
                std::cerr << "LOOP FOUND\n";
                out_arch = *loop_out;
            } else {
                
                trace.push_back(inst->I);
                
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
    
    ByteMap write_mask;
    for (const auto& range : symbolic_ranges) {
        for (uint64_t addr = range.base; addr < range.base + range.len; ++addr) {
            write_mask.insert(addr);
        }
    }
    
    // set return address
    in_arch.mem.write(in_arch.esp, ctx.bv_val(0x42424242, 32), util::null_output_iterator());
    for (uint64_t i = 0; i < 4; ++i) {
        write_mask.insert(in_arch.esp.as_uint64() + i);
    }
    
    auto e = in_arch.mem.read(in_arch.esp, 4, util::null_output_iterator());
    solver.push();
    solver.add(e != 0x42424242);
    assert(solver.check() == z3::unsat);
    solver.pop();
    
    explore_paths_loop(in_arch, solver, write_mask);
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
