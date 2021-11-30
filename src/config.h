#pragma once

#include <vector>
#include <optional>

#include "pool.h"

namespace x86 {

struct MemoryRange;

}

namespace conf {

extern bool deterministic;

extern std::vector<x86::MemoryRange> symbolic_ranges;
extern std::optional<uint64_t> entrypoint;

extern ThreadPool pool;
extern bool parallel;

}
