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
using AddrSet = std::unordered_set<addr_t>;
using AddrMap = std::unordered_map<addr_t, AddrSet>;
using AddrVec = std::vector<addr_t>;

struct MemoryRange {
    uint64_t base;
    uint64_t len;
};

std::ostream& dump_trace(std::ostream& os, const std::vector<const cs_insn *>& trace);
void dump_trace(const std::string& path, const std::vector<const cs_insn *>& trace);

}
