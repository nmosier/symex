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


void Context::explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr, ByteMap write_mask) {
    
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
    ReadVec reads;
    WriteVec writes;
    inst.transfer(arch, std::back_inserter(reads), std::back_inserter(writes));
    ArchState out_arch = arch;
    // out_arch.create(next_id++, solver);
    
    if (writes.size() == 0) {
        assert(z3::eq(out_arch.mem.mem, in_arch.mem.mem));
    }
    

    std::cerr << "inst @ " << syms.desc(addr) << " : "  << inst.I->mnemonic << " " << inst.I->op_str << "\n";
    
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
    {
        z3::expr_vector v {ctx};
        v.push_back(e != 0x42424242);
        assert(solver.check(v) == z3::unsat);
    }
 
#if 0
    explore_paths_loop(in_arch, solver, write_mask);
#elif 1
    explore_paths_rec(program.program, in_arch, solver, in_arch.eip.get_numeral_uint64(), write_mask);
#else
    explore_paths_rec2(program.program, in_arch, in_arch.eip.get_numeral_uint64(), solver, write_mask);
#endif
}




void Context::explore_paths_rec_dst(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask) {
        
    if (out_arch.eip.simplify().is_numeral()) {
        
        explore_paths_rec(program, out_arch, solver, out_arch.eip.simplify().get_numeral_uint64(), write_mask);
        
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
                explore_paths_rec(program, out_arch, solver, eip.get_numeral_uint64(), write_mask);
            }
            solver.pop();
            solver.add(eip != out_arch.eip);
            ++count;
        }
        
    }
}

void Context::explore_paths_rec_read(Program& program, const ArchState& in_arch, ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const ReadVec& reads, const WriteVec& writes, ReadVec::const_iterator read_it) {
    
    if (read_it == reads.end()) {
        explore_paths_rec_write(program, in_arch, out_arch, solver, write_mask, writes, writes.begin());
        return;
    }
    
    const auto& sym_read = *read_it;

    std::vector<z3::expr> vec;
    z3::enumerate(solver, sym_read.addr, std::back_inserter(vec));
    assert(!vec.empty());
    
    if (vec.size() == 1) {
        
        Read con_read {vec.front(), sym_read.data};
        con_read.data = con_read(core, write_mask);
#if 0
        solver.add(sym_read.data == con_read.data);
#else
        {
            z3::expr_vector src {ctx}, dst {ctx};
            src.push_back(sym_read.data); dst.push_back(con_read.data);
            out_arch.substitute(src, dst);
        }
#endif
        explore_paths_rec_read(program, in_arch, out_arch, solver, write_mask, reads, writes, std::next(read_it));
        
    } else {
        
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
            
            {
                const z3::scope scope {solver};
                solver.add(con_read == sym_read);
                
#if 1
                // EXPERIMENTAL: replace expression
                {
                    z3::expr_vector src(ctx);
                    z3::expr_vector dst(ctx);
                    src.push_back(sym_read.addr); dst.push_back(con_read.addr);
                    src.push_back(sym_read.data); dst.push_back(con_read.data);
                    
                    out_arch.substitute(src, dst);
                }
#endif
                
                explore_paths_rec_read(program, in_arch, out_arch, solver, write_mask, reads, writes, std::next(read_it));
            }
            solver.add(con_read.addr != sym_read.addr);
            ++count;
        }
        
    }
}

void Context::explore_paths_rec_write(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const WriteVec& writes, WriteVec::const_iterator write_it) {
    if (write_it == writes.end()) {
        explore_paths_rec_dst(program, in_arch, out_arch, solver, write_mask);
        return;
    }
    
    const auto& sym_write = *write_it;
    
    // DEBUG: check for misaligned writes
    std::vector<z3::expr> vec;
    z3::enumerate(solver, sym_write.addr, std::back_inserter(vec));
    assert(!vec.empty());
    
    if (vec.size() == 1) {
        
        Write con_write {vec.front(), sym_write.data};
        ByteMap new_write_mask = write_mask;
        for (std::size_t i = 0; i < sym_write.size(); ++i) {
            new_write_mask.insert(con_write.addr.get_numeral_uint64() + i);
        }
        explore_paths_rec_write(program, in_arch, out_arch, solver, new_write_mask, writes, std::next(write_it));
        
    } else {
        
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
}



}