#pragma once

#include <iostream>
#include <vector>
#include <iterator>
#include <unordered_set>
#include <optional>
#include <variant>

#include "archstate.h"

namespace x86 {

struct Node {
    virtual ~Node() {}
    
    using Read = MemState::Read;
    using Write = MemState::Write;
    using ReadVec = std::vector<Read>;
    using WriteVec = std::vector<Write>;
    using Access = std::variant<Read, Write>;
    using AccessVec = std::vector<Access>;
    using ReadOut = std::back_insert_iterator<ReadVec>;
    using WriteOut = std::back_insert_iterator<WriteVec>;
    using AccessOut = std::back_insert_iterator<AccessVec>;
    
    virtual void transfer(ArchState& arch, ReadOut read_out, WriteOut write_out) const = 0;
    
    virtual addr_t entry() const = 0;
    
    using Trace = std::vector<const cs_insn *>;
    using TraceOut = std::back_insert_iterator<Trace>;
    virtual void add_to_trace(const ArchState& arch, const z3::model& model, TraceOut out) const = 0;
    
    virtual void print(std::ostream& os) const = 0;
    
    using AddrSet = std::unordered_set<addr_t>;
    virtual AddrSet exits() const = 0;
};



}
