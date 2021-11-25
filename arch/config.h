#pragma once

#include <vector>

namespace x86 {

struct MemoryRange;

}

namespace conf {

extern bool deterministic;

extern std::vector<x86::MemoryRange> symbolic_ranges;

}
