#pragma once

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

}
