#pragma once

#include "archstate.h"
#include "memstate.h"

namespace transfer {

using Read = x86::MemState::Read;
using Write = x86::MemState::Write;
using ReadOut = std::back_insert_iterator<std::vector<Read>>;
using WriteOut = std::back_insert_iterator<std::vector<Write>>;
using ByteMap = x86::ByteMap;

typedef void transfer_function_t(x86::ArchState& arch, z3::solver& solver, ReadOut read_out, WriteOut write_out, ByteMap& write_mask, const cores::Core& core);

void sym_nop(x86::ArchState& arch, z3::solver& solver);
void sym_memcpy(x86::ArchState& arch, z3::solver& solver);
void sym_strncat(x86::ArchState& arch, z3::solver& solver);
void sym_strnlen(x86::ArchState& arch, z3::solver& solver);
void sym_strncasecmp(x86::ArchState& arch, z3::solver& solver, ReadOut read_out, WriteOut write_out, ByteMap& write_mask, const cores::Core& core);

}
