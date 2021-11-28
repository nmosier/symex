#include <fstream>
#include <sstream>
#include <gperftools/profiler.h>

#include "x86.h"
#include "program.h"
#include "context.h"
#include "util.h"
#include "peephole.h"
#include "config.h"

namespace x86 {

void Context::dump_trace(const z3::model& model) {
    std::stringstream ss;
    ss << "trace" << trace_counter++ << ".asm";
    std::ofstream ofs {ss.str()};
    
    /* print out symbolic ranges */
    const auto init_mem = MemState::get_init_mem(ctx);
    for (const auto& sym_range : symbolic_ranges) {
        z3::expr_vector v {ctx};
        for (uint64_t i = 0; i < sym_range.len; ++i) {
            const z3::expr addr = ctx.bv_val(sym_range.base + i, 32);
            v.push_back(init_mem[addr]);
        }
        if (!v.empty()) {
            ofs << std::hex << sym_range.base << ":" << sym_range.len << " = " << model.eval(z3::concat(v), true) << "\n";
        }
    }
    
    /* print out instructions */
    for (const cs_insn *I : trace) {
        ofs << std::hex << I->address << ": " << I->mnemonic << " " << I->op_str << "\n";
    }

    std::cerr << "dumped trace to " << ss.str() << "\n";
}


void Context::explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr) {
    
    // add instructions until branch
    
    if (program.map.find(addr) == program.map.end()) {
        // find address in core
        const auto seg_it = std::find_if(core.segments_begin(), core.segments_end(), [&] (const cores::Segment& seg) {
            return seg.contains(addr, 1);
        });
        if (seg_it == core.segments_end()) {
            std::cerr << "jump outside of address space: " << std::hex << addr << "\n";
            if (solver.check() != z3::sat) { std::abort(); }
            dump_trace(solver.get_model());
            return;
        }
        // TODO: make this safer
        const void *data = seg_it->at(addr);
        program.disasm((const uint8_t *) data, 16, addr, 1);
    }
    
    const Inst& inst = program.map.at(addr);
    
    trace.push_back(inst.I);
    
    ArchState arch = in_arch;
    
    const auto transfer_it = transfers.find(addr);
    if (transfer_it == transfers.end()) {
        inst.transfer(arch, solver);
    } else {
        transfer_it->second(arch, solver, core);
    }
    
    
    
    ArchState out_arch = arch;
    // out_arch.create(next_id++, solver);

    std::cerr << "inst @ " << std::hex << addr << " " << syms.desc(addr) << " : "  << inst.I->mnemonic << " " << inst.I->op_str << "\n";
    
    I = inst.I;
    
    explore_paths_rec_dst(program, in_arch, out_arch, solver);
    
    trace.pop_back();
}

void Context::explore_paths() {
    z3::solver solver {ctx};
    ArchState in_arch {ctx, core};
    
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
    
    for (const auto& range : symbolic_ranges) {
        in_arch.mem.symbolic(range.base, range.base + range.len);
    }
    
    // set return address
    in_arch.mem.write(in_arch.esp, ctx.bv_val(0x42424242, 32), solver);
    
    auto e = in_arch.mem.read(in_arch.esp, 4, solver);
    {
        z3::expr_vector v {ctx};
        v.push_back(e != 0x42424242);
        assert(solver.check(v) == z3::unsat);
    }
    
    if (conf::entrypoint) {
        in_arch.eip = ctx.bv_val(*conf::entrypoint, 32);
    }
 
    explore_paths_rec(program.program, in_arch, solver, in_arch.eip.get_numeral_uint64());
}




void Context::explore_paths_rec_dst(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver) {
        
    if (out_arch.eip.is_numeral()) {
        
        explore_paths_rec(program, out_arch, solver, out_arch.eip.simplify().get_numeral_uint64());
        
    } else {
        
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
            
            if (conf::deterministic && count > 0) {
                std::cerr << "error: nondeterministic\n";
                std::abort();
            }
            
            const z3::model model = solver.get_model();
            const z3::expr eip = model.eval(out_arch.eip, true);
            // std::cerr << "dst " << eip << "\n";

            solver.push();
            {
                solver.add(eip == out_arch.eip);
                explore_paths_rec(program, out_arch, solver, eip.get_numeral_uint64());
            }
            solver.pop();
            solver.add(eip != out_arch.eip);
            ++count;
        }
        
    }
}





}
