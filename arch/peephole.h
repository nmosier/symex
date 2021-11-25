#pragma once

#include "operands.h"

namespace x86 {

/* We can optimize the program by tracking stack frames separately. Keeping them independent helps break down the problem for the solver. Furthermore, it helps us detect reads from uninitialized stack memory.
 * For each CALL + PUSH EBP + MOV EBP, ESP instruction, we can introduce a new stack frame. For all memory operands [ebp + uint], then
 *
 */


struct Peephole {
    virtual bool operator()(addr_t eip, CoreProgram& program, ArchState& arch, ReadOut read_out, WriteOut write_out) const = 0;
    virtual ~Peephole() {}
};

/* Optimize EIP reads:
 * call label
 * label: pop r32
 * to
 * mov r32, label
 * mov [esp - 4], r32
 *
 * This avoids a read from memory.
 */

struct ReadEIP: Peephole {
    virtual bool operator()(addr_t eip0, CoreProgram& program, ArchState& arch, ReadOut read_out, WriteOut write_out) const override {
        z3::context& ctx = arch.ctx();
        const Inst *I = dynamic_cast<const Inst *>(program.disasm(eip0));
        if (I == nullptr) { return false; }
        if (I->I->id != X86_INS_CALL) { return false; }
        const Operand op {I->x86->operands[0]};
        if (op.op.type != X86_OP_IMM) { return false; }
        const addr_t eip1 = eip0 + I->I->size;
        if (op.op.imm != eip1) { return false; }
        I = dynamic_cast<const Inst *>(program.disasm(eip1));
        if (I == nullptr) { return false; }
        if (I->I->id != X86_INS_POP) { return false; }
        const Operand dst {I->x86->operands[0]};
        if (dst.op.type != X86_OP_REG) { return false; }
        
        // Optimization matches
        const z3::expr eip1_ = ctx.bv_val(eip1, 32);
        arch.mem.write(arch.esp - 4, eip1_, write_out);
        dst.write(arch, eip1_, write_out);
        arch.eip = ctx.bv_val(eip1 + I->I->size, 32);
        
        std::cerr << "MATCH\n";
        return true;
    }
};

}
