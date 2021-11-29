#include <cmath>

#include "operands.h"
#include "archstate.h"
#include "util.h"

namespace x86 {

z3::expr MemoryOperand::addr(ArchState& arch) const {
    z3::context& ctx = arch.ctx();
    z3::expr base =
    mem.base == X86_REG_INVALID ? ctx.bv_val(0, 32) : Register(mem.base).read(arch);
    z3::expr index =
    mem.index == X86_REG_INVALID ? ctx.bv_val(0, 32) : Register(mem.index).read(arch);
    z3::expr index_scaled = z3::shl(index, (unsigned) std::log2(mem.scale));
    z3::expr disp = ctx.bv_val(mem.disp, 32);
    z3::expr addr = base + index_scaled + disp;
    return addr;
}

z3::expr MemoryOperand::read(ArchState& arch, unsigned size, z3::solver& solver) const {
    if (mem.segment != X86_REG_INVALID) {
        std::cerr << "warning: segment address; returning 0\n";
        return arch.ctx().bv_val(0, size * 8);
    }
    
    const z3::expr addr_ = addr(arch);
    return arch.mem.read(addr_, size, solver);
}

void MemoryOperand::write(ArchState& arch, const z3::expr& e, z3::solver& solver) const {
    const z3::expr addr_ = addr(arch);
    arch.mem.write(addr_, e, solver);
}

z3::expr Operand::read(ArchState& arch, z3::solver& solver) const {
    z3::context& ctx = arch.ctx();
    const unsigned bits = op.size * 8;
    switch (op.type) {
        case X86_OP_REG:
            return Register(op.reg).read(arch);
            
        case X86_OP_IMM:
            return ctx.bv_val(op.imm, bits);
            
        case X86_OP_MEM: {
            return MemoryOperand(op.mem).read(arch, op.size, solver);
        }
            
        default:
            std::abort();
    }
}

void Operand::write(ArchState& arch, const z3::expr& e, z3::solver& solver) const {
    if (e.is_bv()) {
        assert(bits() == e.get_sort().bv_size());
    }
    
    switch (op.type) {
        case X86_OP_REG:
            Register(op.reg).write(arch, e);
            break;
            
        case X86_OP_IMM:
            throw std::logic_error("assignment to immediate");
            
        case X86_OP_MEM:
            MemoryOperand(op.mem).write(arch, e, solver);
            break;
            
        default: std::abort();
    }
}


z3::expr Register::read(const ArchState& arch) const {
    switch (reg) {
        case X86_REG_EAX: return arch.eax;
        case X86_REG_EBX: return arch.ebx;
        case X86_REG_ECX: return arch.ecx;
        case X86_REG_EDX: return arch.edx;
            
        case X86_REG_EDI: return arch.edi;
        case X86_REG_ESI: return arch.esi;
            
        case X86_REG_EBP: return arch.ebp;
        case X86_REG_ESP: return arch.esp;
            
        case X86_REG_AX: return arch.eax.extract(15, 0);
        case X86_REG_CX: return arch.ecx.extract(15, 0);
        case X86_REG_DX: return arch.edx.extract(15, 0);
            
        case X86_REG_AL: return arch.eax.extract(7, 0);
        case X86_REG_BL: return arch.ebx.extract(7, 0);
        case X86_REG_CL: return arch.ecx.extract(7, 0);
        case X86_REG_DL: return arch.edx.extract(7, 0);
            
        case X86_REG_AH: return arch.eax.extract(15, 8);
        case X86_REG_DH: return arch.edx.extract(15, 8);
            
        case X86_REG_XMM0: return arch.xmm0;
        case X86_REG_XMM1: return arch.xmm1;
        case X86_REG_XMM2: return arch.xmm2;
        case X86_REG_XMM3: return arch.xmm3;
        case X86_REG_XMM4: return arch.xmm4;
        case X86_REG_XMM5: return arch.xmm5;
        case X86_REG_XMM6: return arch.xmm6;
        case X86_REG_XMM7: return arch.xmm7;
            
        case X86_REG_ST0:
        case X86_REG_ST1:
        case X86_REG_ST2:
        case X86_REG_ST3:
        case X86_REG_ST4:
        case X86_REG_ST5:
        case X86_REG_ST6:
        case X86_REG_ST7: {
            const unsigned idx = reg - X86_REG_ST0;
            return arch.fpu.get(idx);
        }
            
        default:
            unimplemented("reg %s", cs_reg_name(g_handle, reg));
    }
}

void Register::write(ArchState& arch, const z3::expr& e) const {
    switch (reg) {
        case X86_REG_EAX: arch.eax = e; break;
        case X86_REG_EBX: arch.ebx = e; break;
        case X86_REG_ECX: arch.ecx = e; break;
        case X86_REG_EDX: arch.edx = e; break;
            
        case X86_REG_EDI: arch.edi = e; break;
        case X86_REG_ESI: arch.esi = e; break;
            
        case X86_REG_EBP: arch.ebp = e; break;
        case X86_REG_ESP: arch.esp = e; break;
            
        case X86_REG_XMM0: arch.xmm0 = e; break;
        case X86_REG_XMM1: arch.xmm1 = e; break;
        case X86_REG_XMM2: arch.xmm2 = e; break;
        case X86_REG_XMM3: arch.xmm3 = e; break;
        case X86_REG_XMM4: arch.xmm4 = e; break;
        case X86_REG_XMM5: arch.xmm5 = e; break;
        case X86_REG_XMM6: arch.xmm6 = e; break;
        case X86_REG_XMM7: arch.xmm7 = e; break;
            
            
        case X86_REG_AL: arch.eax = z3::bv_store(arch.eax, e, 0); break;
        case X86_REG_BL: arch.ebx = z3::bv_store(arch.ebx, e, 0); break;
        case X86_REG_CL: arch.ecx = z3::bv_store(arch.ecx, e, 0); break;
        case X86_REG_DL: arch.edx = z3::bv_store(arch.edx, e, 0); break;
            
        case X86_REG_AH: arch.eax = z3::bv_store(arch.eax, e, 8); break;
        case X86_REG_DH: arch.edx = z3::bv_store(arch.edx, e, 8); break;
            
        case X86_REG_CX: arch.ecx = z3::bv_store(arch.ecx, e, 0); break;
        case X86_REG_DX: arch.edx = z3::bv_store(arch.edx, e, 0); break;
            
        case X86_REG_ST0:
        case X86_REG_ST1:
        case X86_REG_ST2:
        case X86_REG_ST3:
        case X86_REG_ST4:
        case X86_REG_ST5:
        case X86_REG_ST6:
        case X86_REG_ST7: {
            const unsigned idx = reg - X86_REG_ST0;
            const z3::expr fp = arch.fpu.to_fp(e);
            arch.fpu.set(idx, fp);
            break;
        }
            
        default:
            unimplemented("reg %s", cs_reg_name(g_handle, reg));
    }
}

}
