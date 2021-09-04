#include <iostream>
#include <vector>
#include <variant>
#include <fstream>
#include <optional>
#include <unordered_map>
#include <unordered_set>

#include <z3++.h>

struct Program;

// helper type for the visitor #4
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
// explicit deduction guide (not needed as of C++20)
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

struct ArchState {
  z3::expr acc;
  z3::expr bak;
  z3::expr pc;
  ArchState(z3::context& ctx): acc(ctx), bak(ctx), pc(ctx) {}
  ArchState(const z3::expr& acc, const z3::expr& bak, const z3::expr& pc): acc(acc), bak(bak), pc(pc) {}
};

std::ostream& operator<<(std::ostream& os, const ArchState& arch) {
  os << arch.acc << " " << arch.bak << " " << arch.pc;
  return os;
}

struct ArchStateSort {
  z3::func_decl cons;
  z3::sort sort;
  z3::func_decl acc;
  z3::func_decl bak;
  z3::func_decl pc;
    
  ArchStateSort(z3::context& ctx, const z3::sort& int_sort):
    cons(ctx), sort(ctx), acc(ctx), bak(ctx), pc(ctx) {
    constexpr std::size_t count = 3;
    const char *names[count] = {"ACC", "BAK", "PC"};
    const z3::sort sorts[count] = {int_sort, int_sort, int_sort};
    z3::func_decl_vector projs {ctx};
    cons = ctx.tuple_sort("archstate", 3, names, sorts, projs);
    sort = cons.range();
    acc = projs[0];
    bak = projs[1];
    pc  = projs[2];
  }

  ArchState unpack(const z3::expr& e) const {
    return ArchState {acc(e), bak(e), pc(e)};
  }

  z3::expr pack(const ArchState& t) const {
    return cons(t.acc, t.bak, t.pc);
  }  
};

struct Context {
  z3::context ctx;
  ArchStateSort archstate_sort;
  z3::func_decl archs;
  z3::func_decl path;
  z3::expr idx;
  z3::expr zero;

  unsigned next_id = 0;
  z3::expr constant(const z3::sort& sort) {
    return ctx.constant(std::to_string(next_id++).c_str(), sort);
  }

  ArchState unpack(const z3::expr& e) const { return archstate_sort.unpack(e); }
  z3::expr pack(const ArchState& t) const { return archstate_sort.pack(t); }
  
  Context(): ctx(), archstate_sort(ctx, ctx.int_sort()), archs(ctx), path(ctx),
	     idx(ctx.int_const("idx")),
		 zero(ctx.int_val(0)) {
    constexpr unsigned arity = 1;
    const z3::sort domain[arity] = {ctx.int_sort()};
    const z3::sort range = archstate_sort.sort;
    archs = ctx.function("archs", 1, domain, range);
    path = ctx.function("path", 1, domain, ctx.int_sort());
  }

  z3::expr in_range(const z3::expr& idx, int begin, int end) {
    return idx >= ctx.int_val(begin) && idx < ctx.int_val(end);
  }

  static constexpr int max = 20;
  
  void constrain_init(z3::solver& solver) {
    solver.add(path(zero) == zero, "init0");
    solver.add(archs(zero) == pack(ArchState {zero, zero, zero}), "init1");
  }

  void constrain_transfer(z3::solver& solver, const Program& program);

  void constrain_path(z3::solver& solver) {
    ArchState arch = unpack(archs(idx));
    const z3::expr next_pc = path(idx) == arch.pc;
    const z3::expr f = z3::forall(idx, z3::implies(in_range(idx, 0, max), next_pc));
    solver.add(f, "path");
  }

  void constrain_pc(z3::solver& solver, const Program& program);
  
  void constrain(z3::solver& solver, const Program& program) {
    constrain_init(solver);
    constrain_transfer(solver, program);
    constrain_path(solver);
    constrain_pc(solver, program);

    // NOTE: All these should be unsat.
    // solver.add(!z3::forall(idx, z3::implies(in_range(idx, 0, max), path(idx) == zero)));
    // solver.add(!z3::forall(idx, z3::implies(in_range(idx, 0, max), unpack(out(idx)).pc == 0)));
    // solver.add(!z3::forall(idx, z3::implies(in_range(idx, 0, max), out(idx) == pack(ArchState {zero, zero, zero}))));
    solver.add(z3::exists(idx, in_range(idx, 0, max) && unpack(archs(idx)).acc == 13));
  }
 };

 struct RegBase {};
 struct ACC: RegBase {
   z3::expr operator()(const ArchState& archstate) const {
     return archstate.acc;
   }
 };
 struct BAK: RegBase {
   z3::expr operator()(const ArchState& archstate) const {
     return archstate.bak;
   }
 };
 struct Reg: std::variant<ACC, BAK> {
   z3::expr operator()(const ArchState& archstate) const {
     return std::visit([&] (const auto& x) -> z3::expr {
       return x(archstate);
     }, *this);
   }
 };

 using Int = int;
 struct Operand: std::variant<Int, Reg> {
   z3::expr operator()(z3::context& ctx, const ArchState& archstate) const {
     return std::visit(overloaded {
 	[&] (Int i) { return ctx.int_val(i); },
 	[&] (const Reg& r) { return r(archstate); },
       }, *this);
   }
 };

 struct InstBase {
   void inc_pc(z3::context& ctx, ArchState& arch) const {
     arch.pc = arch.pc + 1;
   }
 };

 struct SourceInstBase: InstBase {
   Operand src;
   SourceInstBase(const Operand& src): src(src) {}
 };

 struct MOV: SourceInstBase {
   MOV(const Operand& src): SourceInstBase(src) {}
   void operator()(z3::context& ctx, ArchState& arch) const {
     arch.acc = src(ctx, arch);
     inc_pc(ctx, arch);
   }
 };

 struct ADD: SourceInstBase {
   ADD(const Operand& src): SourceInstBase(src) {}
   void operator()(z3::context& ctx, ArchState& arch) const {
     arch.acc = arch.acc + src(ctx, arch);
     inc_pc(ctx, arch);
   }
 };

 struct SourceInst: std::variant<MOV, ADD> {
   void operator()(z3::context& ctx, ArchState& arch) const {
     std::visit([&] (const auto& x) { x(ctx, arch); }, *this);
   }
 };

 struct SWP: InstBase {
   void operator()(z3::context& ctx, ArchState& arch) const {
     std::swap(arch.acc, arch.bak);
     inc_pc(ctx, arch);
   }
 };

 struct NEG: InstBase {
   void operator()(z3::context& ctx, ArchState& arch) const {
     arch.acc = -arch.acc;
     inc_pc(ctx, arch);
   }
 };
 #if 0
 struct CMP: InstBase {
   void operator()(z3::context& ctx, ArchState& arch) const {
     arch.acc = z3::ite(arch.acc < arch.bak, -1,
 		       z3::ite(arch.acc == arch.bak, ctx.int_val(0),
 			       ctx.int_val(1)));
     inc_pc(ctx, arch);
   }
 };
 #endif

 struct JumpInstBase: InstBase {
   int pc;
   JumpInstBase(int pc): pc(pc) {}
   void transfer(z3::context& ctx, ArchState& arch, const z3::expr& cond) const {
     arch.pc = z3::ite(cond, ctx.int_val(pc), arch.pc + 1);
   }
 };

struct JMP: JumpInstBase {
  JMP(int pc): JumpInstBase(pc) {}
  void operator()(z3::context& ctx, ArchState& arch) const {
    transfer(ctx, arch, ctx.bool_val(true));
  }
};

 struct JLT: JumpInstBase {
   JLT(int pc): JumpInstBase(pc) {}
   void operator()(z3::context& ctx, ArchState& arch) const {
     transfer(ctx, arch, arch.acc < 0);
   }
 };
 struct JEQ: JumpInstBase {
   JEQ(int pc): JumpInstBase(pc) {}
   void operator()(z3::context& ctx, ArchState& arch) const {
     transfer(ctx, arch, arch.acc == 0);
   }
 };
 struct JGT: JumpInstBase {
   JGT(int pc): JumpInstBase(pc) {}
   void operator()(z3::context& ctx, ArchState& arch) const {
     transfer(ctx, arch, arch.acc > 0);
   }
 };

struct JumpInst: std::variant<JMP, JLT, JEQ, JGT> {
   void operator()(z3::context& ctx, ArchState& arch) const {
     std::visit([&] (const auto& x) { x(ctx, arch); }, *this);
   }
 };

 struct FIN: InstBase {
   void operator()(z3::context& ctx, ArchState& arch) const {
     // NOP
   }
 };

 struct Inst: std::variant<SourceInst, SWP, NEG, JumpInst, FIN> {
   void operator()(z3::context& ctx, ArchState& arch) const {
     std::visit([&] (const auto& x) { x(ctx, arch); }, *this);
   }
 };

 struct Program {
   std::vector<Inst> insts;
 };

 std::optional<Reg> make_reg(const std::string& operand) {
   if (operand == "ACC") {
     return Reg {ACC {}};
   } else if (operand == "BAK") {
     return Reg {BAK {}};
   } else {
     return std::nullopt;
   }
 }

 std::optional<int> make_int(const std::string& s) {
   char *end;
   const int res = strtol(s.c_str(), &end, 0);
   if (*end || s.empty()) {
     return std::nullopt;
   } else {
     return res;
   }
 }

 std::optional<Operand> make_operand(const std::string& operand) {
   if (const auto reg = make_reg(operand)) {
     return Operand {*reg};
   } else if (const auto num = make_int(operand)) {
     return Operand {*num};
   } else {
     return std::nullopt;
   }
 }


 std::optional<SourceInst> make_source_inst(const std::string& opcode, const std::string& operand) {
   if (const auto op = make_operand(operand)) {
     if (opcode == "MOV") {
       return SourceInst {MOV {*op}};
     } else if (opcode == "ADD") {
       return SourceInst {ADD {*op}};
     } else {
       return std::nullopt;
     }
   } else {
     return std::nullopt;
   }
 }

 std::optional<JumpInst> make_jump_inst(const std::string& opcode, const std::string& operand) {
   if (const auto pc = make_int(operand)) {
     if (opcode == "JMP") {
       return JumpInst {JMP {*pc}};
     } else if (opcode == "JLT") {
       return JumpInst {JLT {*pc}};
     } else if (opcode == "JEQ") {
       return JumpInst {JEQ {*pc}};
     } else if (opcode == "JGT") {
       return JumpInst {JGT {*pc}};
     } else {
       return std::nullopt;
     }
   } else {
     return std::nullopt;
   }
 }

 std::optional<Inst> make_inst(const std::string& opcode, const std::string& operand) {
   if (const auto source_inst = make_source_inst(opcode, operand)) {
     return Inst {*source_inst};
   } else if (opcode == "SWP") {
     return Inst {SWP {}};
   } else if (opcode == "NEG") {
     return Inst {NEG {}};
 #if 0
   } else if (opcode == "CMP") {
     return Inst {CMP {}};
 #endif
   } else if (const auto jump_inst = make_jump_inst(opcode, operand)) {
     return Inst {*jump_inst};
   } else if (opcode == "FIN") {
     return Inst {FIN {}};
   } else {
     return std::nullopt;
   }
 }


 /*** CFG CONSTRUCTION ***/
 using NodeRef = unsigned;
 class CFG {
 public:
   using Rel = std::unordered_map<NodeRef, std::unordered_set<NodeRef>>;
   Rel fwd;
   Rel rev;

   void add_edge(NodeRef src, NodeRef dst) {
     fwd[src].insert(dst);
     rev[dst].insert(src);
   }

   std::vector<Inst> nodes;

   Inst& operator[](NodeRef ref) { return nodes.at(ref); }
   const Inst& operator[](NodeRef ref) const { return nodes.at(ref); }

   NodeRef add_node(const Inst& inst) {
     nodes.push_back(inst);
     return nodes.size() - 1;
   }

 private:
 };

 // util: convert variant to base type
 template <typename T, typename... Ts>
 const T *variant_static_cast(const std::variant<Ts...> *v) {
   return std::visit([] (const auto& v) {
     return &static_cast<const T&>(v);
   }, *v);
 }

 CFG construct_cfg(const Program& prog) {
   CFG cfg;
   for (const Inst& inst : prog.insts) {
     const NodeRef cur = cfg.add_node(inst);
     if (const auto *jump = std::get_if<JumpInst>(&inst)) {
       const auto pc = variant_static_cast<JumpInstBase>(jump)->pc;
       cfg.add_edge(cur, pc);
       cfg.add_edge(cur, cur + 1);
     } else if (const auto *fin = std::get_if<FIN>(&inst)) {
       // nothing
     } else {
       cfg.add_edge(cur, cur + 1);
     }
   }
   return cfg;
 }

 // SMT INSTRUCTION SEMANTICS

 void Context::constrain_transfer(z3::solver& solver, const Program& program) {
   const z3::expr arch_in = archs(idx);

   for (std::size_t i = 0; i < program.insts.size(); ++i) {
     ArchState arch = unpack(arch_in);
     const Inst& inst = program.insts[i];
     inst(ctx, arch);
     const z3::expr arch_out = pack(arch);
     std::cerr << "arch_in: " << arch_in << "\n" << "arch_out: " << arch_out << "\n";
     std::cerr << "arch: " << arch << "\n";
     const z3::expr transfer = z3::implies(path(idx) == ctx.int_val(static_cast<int>(i)), archs(idx + 1) == arch_out);
     solver.add(z3::forall(idx, z3::implies(in_range(idx, 0, max), transfer)),
		(std::string("transfer") + std::to_string(i)).c_str());
   }
}

void Context::constrain_pc(z3::solver& solver, const Program& program) {
  const z3::expr f = z3::forall(idx, z3::implies(in_range(idx, 0, max), path(idx) >= 0 && path(idx) < ctx.int_val(static_cast<int>(program.insts.size()))));
  solver.add(f, "pc");
}



int main(int argc, char *argv[]) {

  std::istream *in = &std::cin;

  Program program;

  std::string line;
  while (std::getline(*in, line)) {
    char *s = strdup(line.c_str());

    const char *opcode = strsep(&s, " ");
    const char *operand = strsep(&s, " ");
    if (opcode == nullptr) opcode = "";
    if (operand == nullptr) operand = "";

    if (opcode == nullptr) {
      std::cerr << "missing opcode\n";
      exit(1);
    }

    if (const auto inst = make_inst(opcode, operand)) {
      program.insts.push_back(*inst);
    } else {
      std::cerr << "bad instruction '" << line << "'\n";
      exit(1);
    }

    free(s);
  }

  std::cout << "Parsed " << program.insts.size() << " instructions\n";

  CFG cfg = construct_cfg(program);

  Context ctx;

  // IN, OUT maps
  z3::solver solver {ctx.ctx};

  // CONSTRAINTS
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


	     
