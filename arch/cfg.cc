#include "cfg.h"
#include "program.h"
#include "util.h"
#include "context.h"

namespace x86 {

template <typename OutputIt>
OutputIt CFG::get_successors(addr_t addr, const cs_insn& I, OutputIt out) const {
    const auto& x86 = I.detail->x86;
    switch (I.id) {
        case X86_INS_JMP:
            // check operands
            if (x86.operands[0].type == X86_OP_IMM) {
                *out++ = x86.operands[0].imm;
            }
            break;
            
        case X86_INS_JAE:
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JLE:
        case X86_INS_JL:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JRCXZ:
        case X86_INS_JS:
            *out++ = addr + I.size; // branch not taken
            *out++ = x86.operands[0].imm; // branch taken
            break;
            
        case X86_INS_CALL:
        case X86_INS_RET:
            break;
            
        default:
            *out++ = addr + I.size; // next instruction
            break;
    }
    
    return out;
}

void CFG::add(addr_t addr) {
    AddrVec todo = {addr};
    
    while (!todo.empty()) {
        const addr_t addr = todo.back();
        todo.pop_back();
        
        if (!seen.insert(addr).second) { continue; }
        
        fwd[addr];
        rev[addr];
        
        const Inst *I = program.disasm(addr);
        if (I == nullptr) { continue; }
        
        AddrVec succs;
        get_successors(addr, *I->I, std::back_inserter(succs));
        for (addr_t succ : succs) {
            add_edge(addr, succ);
        }
        
        std::copy(succs.begin(), succs.end(), std::back_inserter(todo));
    }
}

/* MARK: iter.arch should contain initial state (size=1) */
void CFG::Loop::transfer_iteration(Iteration& iter, bool reset_mem) const {
    for (const Inst& I : body) {
        ArchState arch = iter.archs.back();
        auto& reads = iter.reads.emplace_back();
        auto& writes = iter.writes.emplace_back();
        I.transfer(arch, std::back_inserter(reads), std::back_inserter(writes));
        if (reset_mem) {
            arch.mem.mem = iter.archs.back().mem.mem;
        }
        iter.archs.push_back(arch);
    }
}

std::vector<MemState::Access> CFG::Loop::Iteration::accesses() const {
    std::vector<MemState::Access> res;
    for (const auto& rds : reads) {
        for (const auto& rd : rds) {
            res.push_back(rd);
        }
    }
    for (const auto& wrs : writes) {
        for (const auto& wr : wrs) {
            res.push_back(wr);
        }
    }
    return res;
}

void CFG::Loop::Iteration::transform_exprs(std::function<z3::expr (const z3::expr&)> f) {
    for (auto& arch : archs) {
        arch.transform_expr(f);
    }
    
    for (auto& rds : reads) {
        for (auto& rd : rds) {
            rd.transform_expr(f);
        }
    }
    
    for (auto& wrs : writes) {
        for (auto& wr : wrs) {
            wr.transform_expr(f);
        }
    }
}

void CFG::Loop::Iteration::substitute(const z3::expr_vector& src, const z3::expr_vector& dst) {
    transform_exprs([&src, &dst] (z3::expr e) -> z3::expr {
        return e.substitute(src, dst);
    });
}

template <typename OutputIt>
OutputIt CFG::Loop::writes(const z3::expr& begin, const z3::expr& end, OutputIt out) const {
    z3::expr it = begin;
    
    for (z3::expr it = begin; it.id() != end.id(); it = it.arg(0)) {
        assert(it.decl().name().str() == "store");
        *out++ = std::make_pair(it.arg(1), it.arg(2));
    }
    
    return out;
}


void CFG::Loop::Analysis::set_iters_1() {
    // TODO: clean this up a bit.
    // NOTE: Be careful with the pointer when appending to arrays...
    {
        const z3::scope scope {solver};
        const ArchState *next_in = &in;
        while (true) {
            std::cerr << "Checking iteration " << iters.size() << "\n";
            
            iters.push_back(Iteration(*next_in));
            Iteration& iter = iters.back();
            
            /* do next iteration */
            loop.transfer_iteration(iter);
            
            /* check if loop continuation satisfiable */
            solver.add(iter.archs.back().eip == ctx().bv_val(loop.body.front().I->address, 32));
            context.cover_execution(solver, iter.get_reads(), std::inserter(read_set, read_set.end()));
            if (solver.check() != z3::sat) {
                break;
            }
            
            /* prepare for next iteration */
            next_in = &iter.archs.back();
        }
    }
    
    std::cerr << "LOOP ANALYSIS: max iterations: " << iters.size() << "\n";
    
    if (iters.size() <= 2) {
        throw exception("cannot execute minimum iterations");
    }
    
    // apply read set
    context.apply_read_set(solver, read_set.begin(), read_set.end());
}

void CFG::Loop::Analysis::check_aliases_2() {
    z3::scope scope {solver};
    
    // collect all accesses
    ReadVec reads;
    WriteVec writes;
    for (const Iteration& iter : iters) {
        const auto iter_reads = iter.get_reads();
        std::copy(iter_reads.begin(), iter_reads.end(), std::back_inserter(reads));
        const auto iter_writes = iter.get_writes();
        std::copy(iter_writes.begin(), iter_writes.end(), std::back_inserter(writes));
    }
    std::vector<MemState::Access> accesses;
    std::copy(reads.begin(), reads.end(), std::back_inserter(accesses));
    std::copy(writes.begin(), writes.end(), std::back_inserter(accesses));
    
    // look for aliases
    {
        z3::expr alias = ctx().bool_val(false);
        for (auto it1 = accesses.begin(); it1 != accesses.end(); ++it1) {
            for (auto it2 = std::next(it1); it2 != accesses.end(); ++it2) {
                const z3::expr pred = (it1->addr >= it2->addr && it1->addr < it2->addr + ctx().bv_val((unsigned) it2->size(), 32)) || (it2->addr >= it1->addr && it2->addr < it1->addr + ctx().bv_val((unsigned) it1->size(), 32));
                alias = alias || pred;
            }
        }
        
        z3::scope scope {solver};
        solver.add(alias);
        if (solver.check() == z3::sat) {
            throw exception("accesses alias");
        }
    }
}

void CFG::Loop::Analysis::find_access_strides_3() {
    // collect all per-iteration reads, writes
    std::vector<std::vector<MemState::Access>> accesses;
    std::unordered_set<std::size_t> read_counts, write_counts;
    for (const Iteration& iter : iters) {
        const auto reads = iter.get_reads();
        const auto writes = iter.get_writes();
        read_counts.insert(reads.size());
        write_counts.insert(writes.size());
        std::vector<MemState::Access> access;
        std::copy(reads.begin(), reads.end(), std::back_inserter(access));
        std::copy(writes.begin(), writes.end(), std::back_inserter(access));
        accesses.push_back(std::move(access));
    }
    if (read_counts.size() != 1 || write_counts.size() != 1) {
        throw exception("mismatch in reads and writes between iterations");
    }
    const std::size_t read_count = *read_counts.begin();
    const std::size_t write_count = *write_counts.begin();
    const std::size_t access_count = read_count + write_count;
    
    // get stride values
    std::vector<int> strides;
    for (std::size_t i = 0; i < access_count; ++i) {
        std::vector<MemState::Access> group;
        for (const auto& access_set : accesses) {
            group.push_back(access_set.at(i));
        }
        
        z3::scope scope {solver};
        const z3::expr scale = ctx().bv_const("scale", 32);
        z3::expr pred = ctx().bool_val(true);
        const z3::expr ref_addr = group.front().addr;
        for (std::size_t i = 0; i < group.size(); ++i) {
            z3::expr idx = ctx().bv_val((unsigned) i, 32);
            const z3::expr c = ref_addr + scale * idx == group.at(i).addr;
            solver.add(c);
        }
        if (solver.check() != z3::sat) {
            throw exception("could not find scalar to index memory access with");
        }
        
        z3::eval eval {solver.get_model()};
        std::cerr << "LOOP ANALYSIS: access scale: " << eval(scale) << "\n";
    }
}

bool CFG::Loop::Analysis::check_constant_reg(z3::expr ArchState::*reg) {
    const z3::scope scope {solver};
    const z3::expr& in_reg = in.*reg;
    const z3::expr& sym_in_reg = sym_in.*reg;
    const z3::expr& sym_out_reg = sym_out().*reg;
    const unsigned bits = in_reg.get_sort().bv_size();

    z3::expr same = ctx().bool_val(true);
    for (const Iteration& iter : iters) {
        const z3::expr& out_reg = iter.archs.back().*reg;
        same = same && out_reg == in_reg;
    }
    solver.add(!same);
    if (solver.check() == z3::unsat) {
        sym_out_param.*reg = sym_in.*reg;
        const_regs.push_back(reg);
        std::cerr << "constant register " << sym_in_reg << "\n";
        return true;
    } else {
        return false;
    }
}

bool CFG::Loop::Analysis::check_sequential_reg(z3::expr ArchState::*reg) {
    z3::scope scope {solver};
    const z3::expr& sym_in_reg = sym_in.*reg;
    const z3::expr& sym_out_reg = sym_out().*reg;
    const z3::expr& in_reg = in.*reg;
    const unsigned bits = in_reg.get_sort().bv_size();
    const z3::expr scalar = ctx().bv_const("scalar", bits);
    
    z3::expr match = ctx().bool_val(true);
    for (std::size_t i = 0; i < iters.size(); ++i) {
        const Iteration& iter = iters.at(i);
        const z3::expr& out_reg = iter.archs.back().*reg;
        const z3::expr idx = ctx().bv_val(static_cast<uint64_t>(i), bits);
        match = match && (out_reg == in_reg + scalar * (idx + 1));
    }
    
    // TODO: this pattern appears multiple times, maybe extract?
    z3::expr_vector exists_match {ctx()};
    exists_match.push_back(match);

    for (unsigned i = 0; i < 1 && solver.check(exists_match) == z3::sat; ++i) {
        const z3::eval eval {solver.get_model()};
        const z3::expr con_scalar = eval(scalar);
        std::cerr << __FUNCTION__ << ": " << sym_in.*reg << ": con_scalar == " << con_scalar << "\n";
        z3::expr_vector not_all_match {ctx()};
        not_all_match.push_back(scalar == con_scalar && !match);
        if (solver.check(not_all_match) == z3::unsat) {
            sym_out_param.*reg = sym_in.*reg + con_scalar * (idx + 1);
            seq_regs.push_back(reg);
            return true;
        }
        solver.add(scalar != con_scalar);
    }
    
    return false;
}

void CFG::Loop::Analysis::check_combinatorial_reg(z3::expr ArchState::*reg) {
    std::cerr << "Checking combinatorial register " << sym_in.*reg << "\n";
    
    z3::scope scope {solver};
    
    z3::expr acc = sym_out().*reg;
    std::vector<z3::expr> offsets;
    assert(seq_regs.size() > 0);
    for (const auto seq_reg : seq_regs) {
        z3::expr seq_reg_out = sym_out_param.*seq_reg;
        const z3::expr offset = z3::sext(ctx().bv_const((std::string("offset") + std::to_string(offsets.size())).c_str(), 1), 31);
        offsets.push_back(offset);
        // offset can be -1 or 0
        seq_reg_out = z3::substitute(seq_reg_out, idx, idx + offset);
        acc = z3::substitute(acc, sym_in.*seq_reg, seq_reg_out);
    }
    
    // do symbolic replacement
    // TODO: also substitute mem in archstate? or add substitute all to MemState
    z3::expr con_acc = ArchState::substitute(acc, sym_in, in);
    con_acc = z3::substitute(con_acc, sym_in.mem.mem, in.mem.mem);
    
#if 1
    {
        while (true) {
            // find a binding of offset
            for (std::size_t i = 0; i < iters.size(); ++i) {
                std::cerr << "\r" << i << "/" << iters.size();
                const Iteration& iter = iters.at(i);
                z3::expr con_acc_iter = z3::substitute(con_acc, idx, ctx().bv_val((uint64_t) i, 32));
                solver.add(con_acc_iter == iter.archs.back().*reg);
                if (solver.check() != z3::sat) {
                    throw exception("failed to find combinatorial offsets");
                }
            }
            std::cerr << "\n";
            
            assert(solver.check() == z3::sat);
            
            
            z3::expr_vector srcs {ctx()}, dsts {ctx()};
            const z3::eval eval {solver.get_model()};
            z3::expr binding = ctx().bool_val(true);
            for (const z3::expr& offset : offsets) {
                srcs.push_back(offset);
                dsts.push_back(eval(offset));
                binding = binding && offset == eval(offset);
            }
            
            // check whether binding works
            std::cerr << __FUNCTION__ << ": testing offsets " << binding << "\n";
            
            if (check_arch_state_reg(reg, con_acc.substitute(srcs, dsts))) {
                break;
            }
            solver.add(!binding);
        }
    }
#endif
    
#if 0
    for (std::size_t i = 0; i < iters.size(); ++i) {
        z3::expr con_acc_iter = z3::substitute(con_acc, idx, ctx().bv_val((uint64_t) i, 32));
        solver.add(con_acc_iter == iters.at(i).archs.back().*reg, std::to_string(i).c_str());
        assert(solver.check() == z3::sat);
        std::cerr << i << "\n";
    }
    
    if (solver.check() != z3::sat) {
        std::stringstream ss;
        ss << "register " << sym_in.*reg << " not combinatorial";
        throw exception(ss.str());
    }
#endif

    // substitute in replacements
    z3::eval eval {solver.get_model()};
    for (const z3::expr& offset : offsets) {
        acc = z3::substitute(acc, offset, eval(offset));
    }
    sym_out_param.*reg = acc;
}


bool CFG::Loop::Analysis::check_arch_state_reg(z3::expr ArchState::*reg, const z3::expr& test_reg) {
    for (std::size_t i = 0; i < iters.size(); ++i) {
        z3::scope scope {solver};
        const Iteration& iter = iters.at(i);
        z3::expr test_reg_con = test_reg;
        test_reg_con = z3::substitute(test_reg_con, idx, ctx().bv_val((uint64_t) i, 32));
        
        solver.add(iter.archs.back().*reg != test_reg_con);
        
        if (solver.check() != z3::unsat) {
            return false;
        }
    }
    
    return true;
}

void CFG::Loop::Analysis::set_out_param_4() {
    // get symbolic iteration
    Iteration sym_iter {sym_in};
    loop.transfer_iteration(sym_iter, true);
    const ArchState& sym_out = sym_iter.archs.back();
    
    sym_iters.push_back(sym_iter);
    for (std::size_t i = 1; i < iters.size(); ++i) {
        Iteration iter {sym_iter.archs.back()};
        loop.transfer_iteration(iter, true);
        sym_iters.push_back(iter);
    }
    assert(sym_iters.size() == iters.size());
    
    // identify sequential registers
    sym_out_param = sym_out;
    
    // TODO: make check_* function interface more intuitive
    ArchState::for_each(ArchState::REG, [&] (const auto reg) {
        if (!check_constant_reg(reg)) {
            if (!check_sequential_reg(reg)) {
                comb_regs.push_back(reg);
            }
        }
    });
    ArchState::for_each(ArchState::FLAG | ArchState::XMM, [&] (const auto reg) {
        if (!check_constant_reg(reg)) {
            comb_regs.push_back(reg);
        }
    });

    std::cerr << "LOOP ANALYSIS: constant & sequentials:\n";
#define ENT(name, ...) std::cerr << #name << ": " << sym_out_param.name << "\n";
    X_x86_ALL(ENT, ENT);
#undef ENT
    
    for (const auto comb_reg : comb_regs) {
        check_combinatorial_reg(comb_reg);
    }
    
    std::cerr << "LOOP ANALYSIS: symbolic state:\n";
#define ENT(name, ...) std::cerr << #name << ": " << sym_out_param.name << "\n";
    X_x86_ALL(ENT, ENT);
#undef ENT
    
    // get archstate out param
    // ArchState out_param {ctx()};
    {
        z3::expr_vector srcs {ctx()}, dsts {ctx()};
        ArchState::for_each([&] (const auto reg) {
            srcs.push_back(sym_in.*reg);
            dsts.push_back(in.*reg);
        });
        srcs.push_back(sym_in.mem.mem);
        dsts.push_back(in.mem.mem);
        ArchState::for_each([&] (const auto reg) {
            out_param.*reg = (sym_out_param.*reg).substitute(srcs, dsts);
        });
    }
    
    // assert that architectural state stays the same
    for (std::size_t i = 0; i < iters.size(); ++i) {
        z3::scope scope {solver};
        const Iteration& iter = iters.at(i);
        z3::expr_vector srcs {ctx()}, dsts {ctx()};
        srcs.push_back(idx);
        dsts.push_back(ctx().bv_val((uint64_t) i, 32));
        ArchState out_param_con = out_param;
        out_param_con.substitute(srcs, dsts);
        solver.add(!(iter.archs.back() == out_param_con), std::to_string(i).c_str());
        const auto res = solver.check();
        std::cerr << i << " " << res << "\n";
        if (res != z3::unsat) {
            z3::eval eval {solver.get_model()};
#define ENT(name, ...) std::cerr << #name << " " << eval(iter.archs.back().name) << " " << eval(out_param_con.name) << "\n";
            X_x86_ALL(ENT, ENT);
#undef ENT
            std::stringstream ss;
            ss << "iteration " << i << " not equal";
            throw exception(ss.str());
        }
    }
    
    // create iteration count
    static unsigned junk = 0;
    num_iters = ctx().bv_const((std::string("num_iters") + std::to_string(junk++)).c_str(), 32);
    const z3::expr max_iters = ctx().bv_val((uint64_t) iters.size(), 32);
    {
        z3::expr_vector src {ctx()}, dst {ctx()};
        src.push_back(idx);
        dst.push_back(num_iters - 1);
        out_param.substitute(src, dst); // TODO: overload function to accept one parameter
    }
    solver.add(num_iters > 0 && num_iters <= max_iters);
    solver.add(out_param.eip != ctx().bv_val(loop.body.front().I->address, 32));
    
    // formulate memory modifications
    {
        z3::expr acc = in.mem.mem;
        for (std::size_t i = 0; i < iters.size(); ++i) {
            const Iteration& iter = iters.at(i);
            const auto writes = iter.get_writes();
            for (const MemState::Write& write : writes) {
                for (unsigned i = 0; i < write.size(); ++i) {
                    const z3::expr data = write.data.extract((i + 1) * 8 - 1, i * 8);
                    const z3::expr addr = write.addr + ctx().bv_val(i, 32);
                    acc = z3::conditional_store(acc, addr, data, ctx().bv_val((uint64_t) i, 32) < num_iters);
                }
            }
        }
        out_param.mem.mem = acc;
    }
}

bool CFG::Loop::Analysis::compute_niters_5() {
    const z3::scope scope {solver};
    
    // check whether there are multiple iteration values
    std::vector<z3::expr> possible_niters;
    z3::enumerate(solver, num_iters, std::back_inserter(possible_niters));
    std::cerr << __FUNCTION__ << ": possible niters: " << possible_niters.size() << "\n";
    
    if (possible_niters.size() == 1) {
        // this loop repeats a constant number of times
        std::cerr << "LOOP ANALYSIS: constant number of iterations: " << possible_niters.front() << "\n";
        out_param.substitute(z3::make_expr_vector(ctx(), num_iters),
                             z3::make_expr_vector(ctx(), possible_niters.front()));
        return true;
    }
    
    
    /* try to get concise expression for number of iterations
     * Approach: use linear combination of input parameters.
     * NOTE: this will fail for most loops, but is a good start
     */
    z3::expr_vector variables {ctx()};
    z3::expr niters_expr = build_niters_expr(sym_in, variables);
    std::cerr << "niters_expr: " << niters_expr << "\n";
    std::cerr << "variables: " << variables << "\n";
    
    z3::expr_vector preds {ctx()};
    for (unsigned i = 0; i < iters.size(); ++i) {
        const Iteration& iter = iters.at(i);
        const ArchState& in = iter.archs.front();
        const z3::expr niters_expr_i = ArchState::substitute(niters_expr, sym_in, in);
        const z3::expr pred = niters_expr_i + ctx().bv_val(i, 32) == num_iters;
        preds.push_back(pred);
    }
    
    z3::expr_vector variables_con {ctx()};
    if (!z3::satisfying_assignment(solver, z3::reduce_and(preds), variables, variables_con)) {
        std::cerr << "LOOP ANALYSIS: " << __FUNCTION__ << ": couldn't find niters expression\n";
        return false;
    }
    
    // const z3::expr linear_combo_con = linear_combo.substitute(scalars, scalars_con);
    std::cerr << "LOOP ANALYSIS: " << __FUNCTION__ << ": found niters expression: " << niters_expr.substitute(variables, variables_con) << "\n";
}

z3::expr CFG::Loop::Analysis::build_niters_expr(const ArchState& in, z3::expr_vector& variables) {
    const z3::expr constant = ctx().bv_const("constant", 32);
    variables.push_back(constant);
    
    z3::expr linear_combo = constant;
    for (unsigned i = 0; i < seq_regs.size(); ++i) {
        const auto seq_reg = seq_regs.at(i);
        const z3::expr scalar = ctx().bv_const(util::to_string("scalar", i).c_str(), 32);
        variables.push_back(scalar);
        linear_combo = linear_combo + in.*seq_reg * scalar;
    }
    
    return linear_combo;
}

std::optional<ArchState> CFG::Loop::Analysis::analyze() {
    try {
        /* require only one exit for now */
        if (!(loop.exits.size() == 1 && loop.exits.begin()->I == loop.body.back().I)) {
            throw exception("bad exit placement");
        }
        
        set_iters_1();
        check_aliases_2();
        find_access_strides_3();
        set_out_param_4();
        compute_niters_5();
        
        return out_param;
    } catch (const exception& exc) {
        std::cerr << "LOOP ANALYSIS: failed: " << exc.reason << "\n";
        return std::nullopt;
    }
}

}
