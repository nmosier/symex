#include <cassert>
#include <stdexcept>
#include <mach-o/loader.h>
#include <array>

#include "core.hh"
#include "macho.hh"
#include "minidump.hh"

namespace cores {

  Core *Core::Create(const char *path) {
    Create_t * const arr[] = {
      &MachOCore::Create,
      &Minidump::Create,
    };

    for (const auto& create : arr) {
      try {
	const auto core = create(path);
	core->parse();
	return core;
      } catch (ParseError& e) {
	// skip
      }
    }

    throw ParseError("unrecognized coredump format");
  }

  Core::Create_t *Core::Creator(const char *s) {
    if (strcmp(s, "macho") == 0) {
      return &MachOCore::Create;
    } else if (strcmp(s, "minidump") == 0) {
      return &Minidump::Create;
    } else {
      return nullptr;
    }
  }
			     
}
