#pragma once

#include "x86.h"
#include "inst.h"

namespace x86 {

struct Program {
    cs::handle handle {CS_ARCH_X86, CS_MODE_32};
    std::vector<cs::insns> insns;
    std::map<addr_t, Inst> map;
    using BasicBlock = std::vector<Inst>;
    std::map<addr_t, BasicBlock> blocks;
    
    Program() {
        handle.detail(true);
    }
    
    std::size_t disasm(const uint8_t *data, std::size_t size, uint32_t address, std::size_t count = 0) {
        cs::insns new_insns;
        count = handle.disasm(data, size, address, count, new_insns);
        assert(new_insns.size() == count);
        for (cs_insn& new_insn : new_insns) {
            const Inst inst {&new_insn};
            map.emplace(new_insn.address, inst);
        }
        insns.push_back(std::move(new_insns));
        return count;
    }
    
    template <typename Container>
    std::size_t disasm(const Container& container, uint32_t address, std::size_t count = 0) {
        return disasm(container.data(), container.size() * sizeof(container.data()[0]), address, count);
    }
    
    const Inst& at(addr_t addr) const {
        return map.at(addr);
    }
    
    void compute_basic_blocks();
};

struct CoreProgram {
    Program program;
    const cores::MachOCore& core;
    
    CoreProgram(const cores::MachOCore& core): core(core) {}
    
    const Inst *disasm(addr_t addr) {
        if (program.map.find(addr) == program.map.end()) {
            // find address in core
            const auto seg_it = std::find_if(core.segments_begin(), core.segments_end(), [&] (const cores::Segment& seg) {
                return seg.contains(addr, 1);
            });
            if (seg_it == core.segments_end()) {
                return nullptr;
            }
            // TODO: make this safer
            const void *data = seg_it->at(addr);
            program.disasm((const uint8_t *) data, 16, addr, 1);
        }
        
        return &program.map.at(addr);
    }
    
    const Inst& at(addr_t addr) const {
        return program.at(addr);
    }
};

}
