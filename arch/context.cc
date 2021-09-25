#include "context.h"
#include "util.h"
#include "archstate.h"

namespace x86 {

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
            write_mask.insert(con_write.addr.as_uint64() + i);
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
            std::cerr << "DSTS: " << in_arch.eip << "\n";
            std::abort();
        }
        
    }
#endif
    
    return Assignment {.pred = acc, .eip = static_cast<addr_t>(model.eval(out_arch.eip).as_uint64()), .mask = write_mask};
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
            explore_paths_rec(program, out_arch, solver, eip.as_uint64(), write_mask);
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
                new_write_mask.insert(con_write.addr.as_uint64() + i);
            }
            explore_paths_rec_write(program, in_arch, out_arch, solver, new_write_mask, writes, std::next(write_it));
        }
        solver.pop();
        
        solver.add(sym_write.addr != con_write.addr);
        ++count;
    }
}

void Context::check_accesses(const ReadVec& reads, const WriteVec& writes, z3::solver& solver) {
    for (const auto& read : reads) {
        if (solver.check() != z3::sat) { return; }
        const z3::model model = solver.get_model();
        z3::scope scope {solver};
        solver.add(read.addr != model.eval(read.addr));
        if (solver.check() == z3::sat) {
            report("read at %p has multiple source addresses", (void *) model.eval(read.addr).as_uint64());
        }
    }
    
    for (const auto& write : writes) {
        if (solver.check() != z3::sat) { return; }
        const z3::model model = solver.get_model();
        z3::scope scope {solver};
        solver.add(write.addr != model.eval(write.addr));
        if (solver.check() == z3::sat) {
            report("write at %p has multiple destination addresses", (void *) model.eval(write.addr).as_uint64());
        }
    }
}

void Context::check_operands(const Inst& I, const ArchState& arch, z3::solver& solver) {
    for (unsigned i = 0; i < I.x86->op_count; ++i) {
        const auto& operand = I.x86->operands[i];
        if (operand.type == X86_OP_MEM) {
            const MemoryOperand memop {operand.mem};
            if (memop.mem.index != X86_REG_INVALID) {
                const Register base {memop.mem.base};
                const Register index {memop.mem.index};
                const z3::expr addr = memop.addr(arch) - arch.ctx().bv_val(memop.mem.disp, 32);
                z3::scope scope {solver};
                solver.add(addr < base.read(arch) || addr < index.read(arch));
                if (solver.check() == z3::sat) {
                    report("array access underflow at %p", (void *) I.I->address);
                }
            }
        }
    }
}

}
