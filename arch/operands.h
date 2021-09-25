#pragma once

#include <z3++.h>
#include "capstone++.h"
#include "archstate.h"

namespace x86 {

using ReadOut = std::back_insert_iterator<std::vector<MemState::Read>>;
using WriteOut = std::back_insert_iterator<std::vector<MemState::Write>>;


struct Register {
    x86_reg reg;
    
    Register(x86_reg reg): reg(reg) {}
    
    z3::expr read(const ArchState& arch) const;
    void write(ArchState& arch, const z3::expr& e) const;
};

struct MemoryOperand {
    const x86_op_mem& mem;
    
    MemoryOperand(const x86_op_mem& mem): mem(mem) {}
    
    z3::expr read(const ArchState& arch, unsigned size, ReadOut read_out) const;
    
    void write(ArchState& arch, const z3::expr& e, WriteOut write_out) const;
    
    z3::expr addr(const ArchState& arch) const;
};

struct Operand {
    const cs_x86_op& op;
    
    Operand(const cs_x86_op& op): op(op) {}
    
    z3::expr read(const ArchState& arch, ReadOut read_out) const;
    
    void write(ArchState& arch, const z3::expr& e, WriteOut write_out) const;
    
    unsigned size() const { return op.size; }
    unsigned bits() const { return size() * 8; }
};

}
