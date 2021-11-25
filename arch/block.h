#pragma once

#include "node.h"

namespace x86 {


struct BasicBlock: Node {
    using InstVec = std::vector<Inst *>;
    InstVec insts;
    
    virtual void transfer(ArchState& arch, ReadOut read_out, WriteOut write_out) const override {
        for (const Inst *I : insts) {
            I->transfer(arch, read_out, write_out);
            arch.eip = arch.eip.simplify();
        }
    }
    
    virtual addr_t entry() const override {
        return insts.front()->entry();
    }
    
    virtual void add_to_trace(const ArchState& arch, const z3::model& model, TraceOut out) const override {
        for (const Inst *I : insts) {
            I->add_to_trace(arch, model, out);
        }
    }
    
    virtual void print(std::ostream& os) const override {
        for (const Inst *I : insts) {
            I->print(os);
        }
    }
    
    virtual AddrSet exits() const override {
        return insts.back()->exits();
    }
};


}
