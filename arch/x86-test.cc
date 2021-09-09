#include <vector>
#include <cstdint>

#include "x86.h"

csh g_handle;

int main() {
  x86::Program program;
  g_handle = program.handle.get_handle();

  // read code from stdin
  std::vector<uint8_t> code;
  char c;
  while (std::cin.get(c)) {
    code.push_back(c);
  }
  
  const auto num_insts = program.disasm(code, 0);
  std::cout << "disassembled " << num_insts << " instructions\n";
  assert(program.map.size() == num_insts);

  {
  z3::context ctx;
  x86::ArchState::Sort arch_sort {ctx};

  for (const auto& p : program.map) {
    x86::ArchState arch {ctx, arch_sort};
    p.second(arch);
#if 0
    std::cout << arch << "\n";
#endif
  }
  }


  x86::Context ctx;

  z3::params params {ctx.ctx};
  //  params.set("parallel.enable", true);
  z3::tactic tactic = z3::tactic(ctx.ctx, "simplify") & z3::with(z3::tactic(ctx.ctx, "psmt"),
								 params);
  
  // z3::solver solver {ctx.ctx};
  z3::solver solver = tactic.mk_solver();
  ctx.constrain(solver, program);

  const z3::check_result res = solver.check();
  switch (res) {
  case z3::unsat: {
    std::cout << "unsat\n";
    const auto core = solver.unsat_core();
    for (const z3::expr& e : core) {
      std::cout << e << "\n";
    }
  }
    break;
  case z3::sat: {
    std::cout << "sat\n";
    z3::model model = solver.get_model();
    std::cout << model << "\n";
    
  }
    break;
  case z3::unknown:
    std::cout << "unknown\n";
    break;
  }
  
  
}
