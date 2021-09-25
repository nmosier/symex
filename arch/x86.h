#pragma once

#include <map>
#include <array>
#include <unordered_map>
#include <unordered_set>

#define _XOPEN_SOURCE
#include <mach/i386/processor_info.h>
#include <mach/i386/_structs.h>
#include <i386/_mcontext.h>
#include <ucontext.h>
#include <mach/i386/thread_status.h>

#include <z3++.h>
#include <capstone/capstone.h>
#include "capstone++.h"

extern csh g_handle;

namespace x86 {

using addr_t = uint32_t;
using ByteMap = std::unordered_set<addr_t>;




#if 0
struct CFG {
    using Rel = std::unordered_map<addr_t, std::unordered_set<addr_t>>;
    Rel fwd;
    Rel rev;
    
    void add_edge(addr_t src, addr_t dst) {
        fwd[src].insert(dst);
        fwd[dst].insert(src);
    }
    
    CFG(const Program& prog) {
        add_program(prog);
    }
    
    void add_program(const Program& prog) {
#if 0
        for (const auto& p : prog.map) {
            addr_t src = p.first;
            const auto *I = p.second.I;
            std::optional<addr_t> dst;
            switch (I->id) {
                case X86_INS_JMP: {
                    const auto& op = I->detail->x86.operands[0];
                    if (op.type == X86_OP_IMM) {
                        
                    }
                    
                default: unimplemented("%s", I->mnemonic);
                }
            }
        }
#endif
    }
};
#endif

struct MemoryRange {
    uint64_t base;
    uint64_t len;
};

std::ostream& dump_trace(std::ostream& os, const std::vector<const cs_insn *>& trace);
void dump_trace(const std::string& path, const std::vector<const cs_insn *>& trace);

}
