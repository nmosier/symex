#pragma once

#include <string>

#include <z3++.h>

namespace x86 {

struct exception {
    z3::expr_vector vec;
    
    exception(z3::context& ctx): vec(ctx) {}
    
    z3::context& ctx() const {
        return vec.ctx();
    }
    
    virtual const char *what() const = 0;
    
    void print(std::ostream& os) const {
        os << "BUG: " << what() << ": " << vec << "\n";
    }
};

inline std::ostream& operator<<(std::ostream& os, const exception& e) {
    e.print(os);
    return os;
}

struct segfault: exception {
    segfault(const z3::expr& addr): exception(addr.ctx()) {
        vec.push_back(addr);
    }
    
    virtual const char *what() const override {
        return "segfault";
    }
};

struct ignored_instruction: exception {
    const cs_insn *I;
    std::string s;
    
    ignored_instruction(z3::context& ctx, const cs_insn *I): exception(ctx), I(I) {
        s = std::string(I->mnemonic) + " " + I->op_str;
    }
    
    virtual const char *what() const {
        return s.c_str();
    }
};

}
