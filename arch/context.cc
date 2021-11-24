#include "context.h"
#include "util.h"
#include "archstate.h"

namespace x86 {

void Context::check_accesses(const ReadVec& reads, const WriteVec& writes, z3::solver& solver) {
    for (const auto& read : reads) {
        if (solver.check() != z3::sat) { return; }
        const z3::model model = solver.get_model();
        z3::scope scope {solver};
        solver.add(read.addr != model.eval(read.addr));
        if (solver.check() == z3::sat) {
            report("read at %p has multiple source addresses", (void *) model.eval(read.addr).get_numeral_uint64());
        }
    }
    
    for (const auto& write : writes) {
        if (solver.check() != z3::sat) { return; }
        const z3::model model = solver.get_model();
        z3::scope scope {solver};
        solver.add(write.addr != model.eval(write.addr));
        if (solver.check() == z3::sat) {
            report("write at %p has multiple destination addresses", (void *) model.eval(write.addr).get_numeral_uint64());
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

void Context::check_regs(const ArchState& arch) {
    // esp should be constant
    if (!arch.esp.simplify().is_const()) {
        report("non-constant esp");
    }
}

}
