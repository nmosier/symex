#include <vector>
#include <fstream>
#include <numeric>

#include "capstone++.h"

#include "x86.h"
#include "util.h"

namespace x86 {

std::ostream& dump_trace(std::ostream& os, const std::vector<const cs_insn *>& trace) {
    for (const cs_insn *I : trace) {
        os << std::hex << I->address << ": " << I->mnemonic << " " << I->op_str << "\n";
    }
    return os;
}

void dump_trace(const std::string& path, const std::vector<const cs_insn *>& trace) {
    std::ofstream ofs {path};
    dump_trace(ofs, trace);
}

}
