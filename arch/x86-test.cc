#include <vector>
#include <cstdint>
#define _XOPEN_SOURCE
#include <mach/i386/processor_info.h>
#include <mach/i386/_structs.h>
#include <i386/_mcontext.h>
#include <ucontext.h>
#include <mach/i386/thread_status.h>

#include "x86.h"

csh g_handle;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <core>\n";
        return 1;
    }
    
    const char *core = argv[1];
    
  x86::Program program;
  g_handle = program.handle.get_handle();

#if 0
  // read code from stdin
  std::vector<uint8_t> code;
  char c;
  while (std::cin.get(c)) {
    code.push_back(c);
  }
  
  const auto num_insts = program.disasm(code, 0);
  std::cout << "disassembled " << num_insts << " instructions\n";
  assert(program.map.size() == num_insts);
#endif

    x86::Context ctx {core};
    
    assert(ctx.core.thread(0).flavor == x86_THREAD_STATE32);

    std::cerr << ctx.core.nsegments() << " segments\n";
    
    ctx.explore_paths(program);
  
}
