#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>
#include <numeric>

#include <z3++.h>

#define unimplemented(msg, ...)			\
  fprintf(stderr, "%s:%d: unimplemented: " msg "\n", __FILE__, __LINE__, __VA_ARGS__); \
  std::abort()

#define report(msg, ...) \
fprintf(stderr, "report: " msg "\n", ##__VA_ARGS__)

template <typename T>
T swap_endianness(T in) {
    T out;
    const uint8_t *in_it = (const uint8_t *) &in;
    uint8_t *out_it = (uint8_t *) &out + sizeof(T);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        *--out_it = *in_it++;
    }
    return out;
}

namespace z3 {
template <typename... Args>
expr concat(const expr& a, const expr& b, Args&&... args) {
    std::vector<z3::expr> vec = {a, b, std::forward<Args>(args)...};
    expr_vector evec {a.ctx()};
    for (const z3::expr& e : vec) {
        evec.push_back(e);
    }
    return concat(evec);
}

inline expr bv_store(const expr& acc, const expr& val, unsigned lo) {
    z3::context& ctx = acc.ctx();
    const auto val_bits = val.get_sort().bv_size();
    const auto acc_bits = acc.get_sort().bv_size();
    z3::expr_vector slices {ctx};
    if (lo + val_bits < acc_bits) {
        slices.push_back(acc.extract(acc_bits - 1, lo + val_bits));
    }
    slices.push_back(val);
    if (lo > 0) {
        slices.push_back(acc.extract(lo - 1, 0));
    }
    const z3::expr res = z3::concat(slices);
    assert(res.get_sort().bv_size() == acc.get_sort().bv_size());
    return res;
}

inline expr bv_store(const expr& acc, unsigned val, unsigned hi, unsigned lo) {
    return bv_store(acc, acc.ctx().bv_val(val, hi - lo + 1), lo);
}

inline expr operator==(const z3::expr_vector& a, const z3::expr_vector& b) {
    assert(a.size() == b.size());
    z3::context& ctx = a.ctx();
    z3::expr acc = ctx.bool_val(true);
    for (std::size_t i = 0; i < a.size(); ++i) {
        acc = acc && a[i] == b[i];
    }
    return acc;
}

inline expr bvsign(const z3::expr& e) {
    const unsigned i = e.get_sort().bv_size() - 1;
    return e.extract(i, i);
}


inline expr bvne(const z3::expr& a, const z3::expr& b) {
    return a ^ b;
}

inline expr bveq(const z3::expr& a, const z3::expr& b) {
    return ~bvne(a, b);
}

inline expr bool_to_bv(const z3::expr& e) {
    return z3::ite(e, e.ctx().bv_val(1, 1), e.ctx().bv_val(0, 1));
}

template <typename InputIt>
inline expr concat(InputIt begin, InputIt end) {
    auto it = begin;
    z3::expr acc = *it++;
    while (it != end) {
        acc = z3::concat(acc, *it++);
    }
    return acc;
}

struct eval {
    z3::model model;
    eval(const z3::model& model): model(model) {}
    z3::expr operator()(const z3::expr& e) const { return model.eval(e, true); }
};

struct scope {
    z3::solver& solver;
    scope(z3::solver& solver): solver(solver) { solver.push(); }
    ~scope() { solver.pop(); }
};

inline z3::expr zext_to(const z3::expr& in, const z3::expr& to) {
    const unsigned to_bits = to.get_sort().bv_size();
    const unsigned in_bits = in.get_sort().bv_size();
    assert(in_bits <= to_bits);
    return zext(in, to_bits - in_bits);
}

inline z3::expr conditional_store(const z3::expr& arr, const z3::expr& idx, const z3::expr& val, const z3::expr& cond) {
    return z3::store(arr, idx, z3::ite(cond, val, arr[idx]));
}

inline expr substitute(expr& e, const expr& src, const expr& dst) {
    z3::context& ctx = e.ctx();
    expr_vector srcs {ctx}, dsts {ctx};
    srcs.push_back(src);
    dsts.push_back(dst);
    return e.substitute(srcs, dsts);
}

inline expr dot_product(const z3::expr_vector& x, const z3::expr_vector& y) {
    assert(x.size() == y.size());
    assert(!x.empty());
    context& ctx = x.ctx();
    auto x_it = x.begin();
    auto y_it = y.begin();
    const expr init = *x_it++ * *y_it++;
    return std::transform_reduce(x_it, x.end(), y_it, init, [] (const expr& a, const expr& b) -> expr {
        return a + b;
    }, [] (const expr& a, const expr& b) -> expr {
        return a * b;
    });
}

inline expr iff(const z3::expr& a, const z3::expr& b) {
    assert(a.is_bool());
    assert(b.is_bool());
    return a == b;
}

template <typename... Ts>
inline expr_vector make_expr_vector(context& ctx, Ts&&... exprs) {
    expr_vector v {ctx};
    (v.push_back(exprs), ...);
    return v;
}

inline bool satisfying_assignment(z3::solver& solver, const z3::expr& pred, const z3::expr_vector& variables, z3::expr_vector& assignments) {
    assert(pred.is_bool());
    assert(assignments.empty());
    
    z3::context& ctx = solver.ctx();
    const z3::scope scope {solver};
    
    const z3::expr_vector pred_v = z3::make_expr_vector(ctx, pred);
    while (solver.check(pred_v) == z3::sat) {
        const z3::eval eval {solver.get_model()};
        const z3::scope scope {solver};
        
        z3::expr same_sol = ctx.bool_val(true);
        for (const z3::expr& variable : variables) {
            same_sol = same_sol && variable == eval(variable);
        }
        
        const z3::expr_vector always = z3::make_expr_vector(ctx, same_sol, !pred);
        if (solver.check(always) == z3::unsat) {
            // found satisfying assignment
            for (const z3::expr& variable : variables) {
                assignments.push_back(eval(variable));
            }
            return true;
        }
        
        for (const z3::expr& variable : variables) {
            solver.add(!same_sol);
        }
    }
    return false;
}

template <typename OutputIt>
OutputIt enumerate(z3::solver& solver, const z3::expr& x, OutputIt out) {
    const z3::scope scope {solver};
    
    while (solver.check() == z3::sat) {
        const z3::eval eval {solver.get_model()};
        const z3::expr x_con = eval(x);
        *out++ = x_con;
        solver.add(x != x_con);
    }
    
    return out;
}

inline z3::expr reduce_and(const z3::expr_vector& v) {
    z3::context& ctx = v.ctx();
    return std::reduce(v.begin(), v.end(), ctx.bool_val(true), [] (const z3::expr& a, const z3::expr& b) -> z3::expr {
        return a && b;
    });
}


}


namespace util {

struct null_output_iterator {
    const null_output_iterator& operator++() const { return *this; }
    const null_output_iterator& operator++(int) const { return *this; }
    const null_output_iterator& operator*() const { return *this; }
    
    template <typename T>
    const T& operator=(const T& val) const { return val; }
};

inline std::system_error syserr(const std::string& what = "") {
    return std::system_error(std::error_code(errno, std::generic_category()), what);
}

inline std::string format(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *s;
    if (vasprintf(&s, fmt, ap) < 0) {
        throw syserr();
    }
    const std::string res {s};
    std::free(s);
    va_end(ap);
    return res;
}

}

inline z3::expr operator==(const std::vector<z3::expr>& a, const std::vector<z3::expr>& b) {
    assert(a.size() == b.size());
    assert(a.size() > 0);
    z3::context& ctx = a.front().ctx();
    z3::expr acc = ctx.bool_val(true);
    for (std::size_t i = 0; i < a.size(); ++i) {
        acc = acc && a[i] == b[i];
    }
    return acc;
}


namespace util {

template <typename T>
std::string to_string(const T& x) {
    std::stringstream ss;
    ss << x;
    return ss.str();
}

template <typename... Ts>
std::string to_string(Ts&&... args) {
    // from https://en.cppreference.com/w/cpp/language/parameter_pack
    std::stringstream ss;
    int dummy[sizeof...(Ts)] = { (ss << args, 0)... };
    return ss.str();
}

template <typename T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& a) {
    os << "[";
    for (auto it = a.begin(); it != a.end(); ++it) {
        if (it != a.begin()) {
            os << ", ";
        }
        os << *it;
    }
    os << "]";
    return os;
}

}
