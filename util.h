#pragma once

#include <cstdio>
#include <cstdlib>

#define unimplemented(msg, ...)			\
  fprintf(stderr, "%s:%d: unimplemented: " msg "\n", __FILE__, __LINE__, __VA_ARGS__); \
  std::abort()
