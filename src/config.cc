#include "config.h"
#include "x86.h"
#include "abstract.h"

namespace conf {

bool deterministic = true;
std::vector<x86::MemoryRange> symbolic_ranges;
std::optional<uint64_t> entrypoint;

}
