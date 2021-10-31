#pragma once

#include "arch/archstate.h"

namespace transfer {

typedef void (*transfer_function_t)(x86::ArchState& arch, z3::solver& solver);

void sym_nop(x86::ArchState& arch, z3::solver& solver);
void sym_memcpy(x86::ArchState& arch, z3::solver& solver);
void sym_strncat(x86::ArchState& arch, z3::solver& solver);
void sym_strnlen(x86::ArchState& arch, z3::solver& solver);

}
