#pragma once

#include <string>
#include <cstdio>

using prot_t = int;

namespace PROT {
  constexpr prot_t NONE = 0;
  constexpr prot_t READ = 1;
  constexpr prot_t WRITE = 2;
  constexpr prot_t EXECUTE = 4;
}

static inline std::string to_string(prot_t prot) {
  char buf[4];
  sprintf(buf, "%c%c%c",
	  (prot & PROT::READ) ? 'r' : '-',
	  (prot & PROT::WRITE) ? 'w' : '-',
	  (prot & PROT::EXECUTE) ? 'x' : '-'
	  );
  return std::string(buf);
}

static inline prot_t strtoprot(const char *s) {
  prot_t prot = PROT::NONE;
  while (*s) {
    switch (*s) {
    case 'r':
      prot |= PROT::READ;
      break;
    case 'w':
      prot |= PROT::WRITE;
      break;
    case 'x':
      prot |= PROT::EXECUTE;
      break;
    case '-':
      break;
    default:
      return -1;
    }
    ++s;
  }
  return prot;
}
