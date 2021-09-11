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
}
