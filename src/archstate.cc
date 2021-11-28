#include "archstate.h"
#include "util.h"

namespace x86 {

std::ostream& operator<<(std::ostream& os, const ArchState& arch) {
#define ENT(name, ...) os << #name << ": " << arch.name.simplify() << "\n";
    X_x86_ALL(ENT, ENT);
#undef ENT
    return os;
}

#define ENT_(name, ...) name(ctx)
#define ENT(name, ...) ENT_(name),
ArchState::ArchState(z3::context& ctx):
X_x86_ALL(ENT, ENT_), mem(ctx), fpu(ctx) {
    zero(); // TODO: disable this
}
#undef ENT_
#undef ENT

void ArchState::symbolic() {
#define ENT(name, bits, ...) name = ctx().bv_const(#name, bits);
    X_x86_ALL(ENT, ENT);
#undef ENT
    mem.mem = ctx().constant("tmpmem", ctx().array_sort(ctx().bv_sort(32), ctx().bv_sort(8)));
}

z3::expr ArchState::substitute(z3::expr& e, const ArchState& src, const ArchState& dst) {
    z3::context& ctx = e.ctx();
    z3::expr_vector srcs {ctx}, dsts {ctx};
    
#define ENT(name, ...) srcs.push_back(src.name); dsts.push_back(dst.name);
    X_x86_ALL(ENT, ENT);
#undef ENT
    
    return e.substitute(srcs, dsts);
}

void ArchState::create(unsigned id, z3::solver& solver) {
    simplify();
}

// TODO: this is useless, currently
z3::expr ArchState::operator==(const ArchState& other) const {
#define ENT_(name, ...) name == other.name
#define ENT(name, ...) ENT_(name) &&
    return X_x86_ALL(ENT, ENT_);
#undef ENT
#undef ENT_
}

void ArchState::transform_expr(std::function<z3::expr (const z3::expr&)> f) {
#define ENT(name, ...) name = f(name);
    X_x86_ALL(ENT, ENT);
#undef ENT
    
    mem.mem = f(mem.mem);
}


void ArchState::stackdump(unsigned words, const z3::eval& eval) const {
    for (int i = 0; i < words; ++i) {
        std::cerr << eval(mem.read(esp + i * 4, 4, util::null_output_iterator())) << "\n";
    }
}

}
