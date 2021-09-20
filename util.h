#pragma once

#include <cstdio>
#include <cstdlib>
#include <z3++.h>

#define unimplemented(msg, ...)			\
  fprintf(stderr, "%s:%d: unimplemented: " msg "\n", __FILE__, __LINE__, __VA_ARGS__); \
  std::abort()

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

inline expr& operator+=(expr& acc, int val) {
    return acc = acc + val;
}

inline expr& operator-=(expr& acc, int val) {
    return acc = acc - val;
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

