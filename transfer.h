#pragma once

#include <z3++.h>

#include "arch/archstate.h"

class Transfer {
public:
    bool operator()(x86::ArchState& arch, z3::solver& solver) const {
        return transfer(arch, solver);
    }
    
protected:
    virtual bool transfer(x86::ArchState& arch, z3::solver& solver) const = 0;
    
private:
};
