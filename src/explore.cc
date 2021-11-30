#include <fstream>
#include <sstream>
#include <gperftools/profiler.h>
#include <unistd.h>

#include "x86.h"
#include "program.h"
#include "context.h"
#include "util.h"
#include "peephole.h"
#include "config.h"
#include "exception.h"

namespace x86 {

void Context::dump_trace(const z3::model& model, const ArchState& arch_, const std::string& reason) {
    const ArchState arch = arch_.eval(model);
    std::stringstream ss;
#if 0
    ss << "trace" << trace_counter++ << ".asm";
    std::ofstream ofs {ss.str()};
#else
    std::ofstream ofs;
    while (true) {
        char path[] = "trace-XXXX";
        if (::mktemp(path) == nullptr) {
            throw std::system_error(errno, std::generic_category(), "mktemp");
        }
        
        int fd;
        if ((fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL, 0664)) < 0) {
            if (errno == EEXIST) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "open");
        }
        ::close(fd);
        ss << path;
        ofs.open(path);
        break;
    }
#endif
    
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
    
    /* print out reason */
    ofs << "\n" << reason << "\n";
    
    /* print out instructions */
    for (const cs_insn *I : trace) {
        ofs << std::hex << I->address << ": " << I->mnemonic << " " << I->op_str << "\n";
    }
    
    /* print out state */
    ofs << arch << "\n";
    
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
            dump_trace(solver.get_model(), in_arch, "jump outside address space\n");
            return;
        }
        
        /* check if executable */
        if (!(seg_it->prot & PROT_EXEC)) {
            throw segfault(in_arch.eip);
        }
        
        // TODO: make this safer
        const void *data = seg_it->at(addr);
        program.disasm((const uint8_t *) data, 16, addr, 1);
    }
    
    const Inst& inst = program.map.at(addr);
    
    const auto trace_push = util::scoped_push(trace, inst.I);
    
    ArchState arch = in_arch;
    
    try {
        
        const auto transfer_it = transfers.find(addr);
        if (transfer_it == transfers.end()) {
            inst.transfer(arch, solver);
        } else {
            transfer_it->second(arch, solver, core);
        }
        
    } catch (const exception& e) {
        std::cerr << e << "\n";
        solver.check();
        std::cerr << trace_counter << "\n";
        dump_trace(solver.get_model(), in_arch, e.str());
        return;
    }
    
    ArchState out_arch = arch;
    // out_arch.create(next_id++, solver);

    std::cerr << "inst @ " << std::hex << addr << " " << syms.desc(addr) << " : "  << inst.I->mnemonic << " " << inst.I->op_str << "\n";
    
    I = inst.I;
    
    explore_paths_rec_dst(program, in_arch, out_arch, solver);
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
        
        std::vector<z3::expr> con_eips;
        z3::enumerate(solver, out_arch.eip, std::back_inserter(con_eips));
        const unsigned count = con_eips.size();
        
        if (conf::deterministic && count > 0) {
            std::cerr << "error: nondeterministic\n";
            std::abort();
        }
        
        if (conf::parallel) {
            
#if 0
            std::cerr << "THREADS: " << conf::pool.get() << "\n";
#endif
            
            for (auto con_eip_it = std::next(con_eips.begin()); con_eip_it != con_eips.end(); ++con_eip_it) {
                const auto& con_eip = *con_eip_it;
                
                const pid_t pid = ::fork();
                if (pid < 0) {
                    throw std::system_error(errno, std::generic_category(), "fork");
                } else if (pid == 0) {
                    conf::pool.dec();
                    solver.add(out_arch.eip == con_eip);
                    explore_paths_rec(program, out_arch, solver, con_eip.get_numeral_uint64());
                    std::exit(0);
                }
            }
            
            {
                const z3::expr& con_eip = con_eips.front();
                solver.add(out_arch.eip == con_eip);
                explore_paths_rec(program, out_arch, solver, con_eip.get_numeral_uint64());
            }
            
            conf::pool.inc();
            
            for (std::size_t i = 1; i < con_eips.size(); ++i) {
                while (::wait(nullptr) < 0) {
                    if (errno != EINTR && errno != EAGAIN) {
                        throw std::system_error(errno, std::generic_category(), "wait");
                    }
                }
            }
            
            conf::pool.dec();
            
        } else {
            
            for (const z3::expr& con_eip : con_eips) {
                const z3::scope scope {solver};
                solver.add(out_arch.eip == con_eip);
                explore_paths_rec(program, out_arch, solver, con_eip.get_numeral_uint64());
            }
            
        }
        
    }
}





}
