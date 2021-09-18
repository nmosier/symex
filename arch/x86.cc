#include <vector>
#include <fstream>

#include "capstone++.h"

#include "x86.h"
#include "util.h"

namespace x86 {

ArchState::Sort::Sort(z3::context& ctx): reg(ctx.bv_sort(32)), cons(ctx), sort(ctx), projs(ctx), mem(ctx) {
    constexpr std::size_t nregs = XM_SIZE(X_x86_REGS);
    constexpr std::size_t nflags = XM_SIZE(X_x86_FLAGS);
    constexpr std::size_t size = nregs + nflags;
    const char *names[size] = { XM_STR_LIST(X_x86_REGS), XM_STR_LIST(X_x86_FLAGS) };
    std::vector<z3::sort> sorts;
    for (std::size_t i = 0; i < nregs; ++i) {
        sorts.push_back(reg);
    }
    for (std::size_t i = 0; i < nflags; ++i) {
        sorts.push_back(ctx.bv_sort(1));
    }
    cons = ctx.tuple_sort("x86_archstate", size, names, sorts.data(), projs);
    sort = cons.range();
    
}

ArchState ArchState::Sort::unpack(const z3::expr& e) const {
    ArchState arch {e.ctx(), *this};
#define ENT(name, ...) arch.name = projs[static_cast<unsigned>(Fields::name)](e);
    X_x86_REGS(ENT, ENT);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
    return arch;
}

z3::expr ArchState::Sort::pack(ArchState& arch) const {
    z3::expr_vector v {arch.ctx()};
#define ENT_(name, ...) v.push_back(arch.name)
#define ENT(name, ...) v.push_back(arch.name);
    X_x86_REGS(ENT, ENT_);
    X_x86_FLAGS(ENT, ENT_);
#undef ENT
#undef ENT_
    return cons(v);
}

// TRANSFER FUNCTIONS

z3::expr MemoryOperand::addr(const ArchState& arch) const {
    z3::context& ctx = arch.ctx();
    z3::expr base =
    mem.base == X86_REG_INVALID ? ctx.bv_val(0, 32) : Register(mem.base).read(arch);
    z3::expr index =
    mem.index == X86_REG_INVALID ? ctx.bv_val(0, 32) : Register(mem.index).read(arch);
    switch (mem.scale) {
        case 2:
        case 1:
        case 0:
            break;
        default:
            std::abort();
    }
    z3::expr index_scaled = z3::shl(index, mem.scale);
    z3::expr disp = ctx.bv_val(mem.disp, 32);
    z3::expr addr = base + index_scaled + disp;
    return addr;
}

template <typename OutputIt>
z3::expr MemoryOperand::read(const ArchState& arch, unsigned size, OutputIt read_out) const {
    const z3::expr addr_ = addr(arch);
    return arch.mem.read(addr_, size, read_out);
}

template <typename OutputIt>
void MemoryOperand::write(ArchState& arch, const z3::expr& e, OutputIt write_out) const {
    const z3::expr addr_ = addr(arch);
    arch.mem.write(addr_, e, write_out);
}

template <typename OutputIt>
z3::expr Operand::read(const ArchState& arch, OutputIt read_out) const {
    z3::context& ctx = arch.ctx();
    const unsigned bits = op.size * 8;
    switch (op.type) {
        case X86_OP_REG:
            return Register(op.reg).read(arch);
            
        case X86_OP_IMM:
            return ctx.bv_val(op.imm, bits);
            
        case X86_OP_MEM: {
            return MemoryOperand(op.mem).read(arch, op.size, read_out);
        }
            
        default:
            std::abort();
    }
}

template <typename OutputIt>
void Operand::write(ArchState& arch, const z3::expr& e, OutputIt write_out) const {
    switch (op.type) {
        case X86_OP_REG:
            Register(op.reg).write(arch, e);
            break;
            
        case X86_OP_IMM:
            throw std::logic_error("assignment to immediate");
            
        case X86_OP_MEM:
            MemoryOperand(op.mem).write(arch, e, write_out);
            break;
            
        default: std::abort();
    }
}

template <typename OutputIt1, typename OutputIt2>
void Inst::transfer(ArchState& arch, OutputIt1 read_out, OutputIt2 write_out) const {
    z3::context& ctx = arch.ctx();
    std::optional<z3::expr> eip;
    const auto nops = x86->op_count;
    const auto *ops = x86->operands;
    switch (I->id) {
        case X86_INS_NOP:
            break;
        case X86_INS_NEG: {
            const cs_x86_op& op = I->detail->x86.operands[0];
            const Operand op2 {op};
            const z3::expr res = -op2.read(arch, read_out);
            op2.write(arch, res, write_out);
            arch.cf = z3::bvredor(res);
            break;
        }
        case X86_INS_NOT: {
            const cs_x86_op& op = I->detail->x86.operands[0];
            const Operand op2 {op};
            const z3::expr res = ~op2.read(arch, read_out);
            op2.write(arch, res, write_out);
            break;
        }
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_OR:
        case X86_INS_XOR:
        case X86_INS_AND:
        case X86_INS_MOV:
        case X86_INS_TEST:
        case X86_INS_CMP:
            transfer_acc_src(arch, read_out, write_out);
            break;
            
        case X86_INS_RET:
            eip = arch.mem.read(arch.esp, 4, read_out);
            arch.esp = arch.esp + 4;
            break;
            
        case X86_INS_POP: {
            const Operand op {I->detail->x86.operands[0]};
            op.write(arch, arch.mem.read(arch.esp, 4, read_out), write_out);
            arch.esp = arch.esp + 4;
            break;
        }
            
        case X86_INS_PUSH: {
            const Operand op {I->detail->x86.operands[0]};
            arch.esp = arch.esp - 4;
            arch.mem.write(arch.esp, op.read(arch, read_out), write_out);
            break;
        }
            
        case X86_INS_CALL: {
            const Operand op {I->detail->x86.operands[0]};
            arch.esp = arch.esp - 4;
            arch.mem.write(arch.esp, arch.eip + I->size, write_out);
            eip = op.read(arch, read_out);
            break;
        }
            
        case X86_INS_JMP: {
            const Operand op {I->detail->x86.operands[0]};
#if 0
            eip = arch.eip + I->size + op.read(arch, read_out);
#else
            eip = op.read(arch, read_out);
#endif
            break;
        }
            
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JNE:
            transfer_jcc(arch, ctx, read_out, write_out);
            eip = arch.eip;
            break;
            
        case X86_INS_STOSD:
            transfer_string(arch, ctx, read_out, write_out);
            break;
            
        case X86_INS_LEA: {
            const Register dst {x86->operands[0].reg};
            const MemoryOperand src {x86->operands[1].mem};
            dst.write(arch, src.addr(arch));
            break;
        }
            
        case X86_INS_CMOVA:
            transfer_cmovcc(arch, ctx, read_out, write_out);
            break;
            
        case X86_INS_SHR:
            transfer_shift(arch, ctx, read_out, write_out);
            break;
            
        case X86_INS_MOVSB:
            transfer_string_rep(arch, ctx, read_out, write_out);
            eip = arch.eip;
            break;
            
        default: unimplemented("%s", I->mnemonic);
    }
    
    if (!eip) {
        eip = arch.eip + I->size;
    }
    arch.eip = *eip;
}

z3::expr Inst::transfer_acc_src_arith(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                  const z3::expr& src, unsigned bits) const {
    z3::expr res {ctx};
    const z3::expr z = ctx.bv_val(0, 1);
    const z3::expr acc_z = concat(z, acc);
    const z3::expr src_z = concat(z, src);
    z3::expr res_x {ctx};
    
    switch (id) {
        case X86_INS_ADD:
            res_x = acc_z + src_z;
            break;
            
        case X86_INS_SUB:
            res_x = acc_z - src_z;
            break;
            
        default: unimplemented("%s", I->mnemonic);
    }
    
    res = res_x.extract(bits - 1, 0);
    
    // update flags
    arch.cf = res_x.extract(bits, bits);
    arch.zf = ~z3::bvredor(res);
    arch.sf = res.extract(bits - 1, bits - 1);
    
    return res;
}

z3::expr Inst::transfer_acc_src_logic(unsigned id, ArchState& arch, z3::context& ctx, const z3::expr& acc,
                                  const z3::expr& src, unsigned bits) const {
    z3::expr res {ctx};
    
    switch (id) {
        case X86_INS_AND:
            res = acc & src;
            break;
        case X86_INS_OR:
            res = acc | src;
            break;
        case X86_INS_XOR:
            res = acc ^ src;
            break;
        default: unimplemented("%s", I->mnemonic);
    }
    
    // update flags
    arch.cf = ctx.bv_val(0, 1);
    arch.zf = ~z3::bvredor(res);
    arch.sf = res.extract(bits - 1, bits - 1);
    
    return res;
}

template <typename OutputIt1, typename OutputIt2>
void Inst::transfer_acc_src(ArchState& arch, OutputIt1 read_out, OutputIt2 write_out) const {
    z3::context& ctx = arch.ctx();
    const Operand acc_op {I->detail->x86.operands[0]};
    const Operand src_op {I->detail->x86.operands[1]};
    z3::expr acc = acc_op.read(arch, read_out);
    const z3::expr src = src_op.read(arch, read_out);
    
    switch (I->id) {
        case X86_INS_ADD:
        case X86_INS_SUB:
            acc = transfer_acc_src_arith(I->id, arch, ctx, acc, src, acc_op.bits());
            break;
            
        case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_XOR:
            acc = transfer_acc_src_logic(I->id, arch, ctx, acc, src, acc_op.bits());
            break;
            
        case X86_INS_MOV:
            acc = src;
            break;
            
        case X86_INS_TEST:
            transfer_acc_src_logic(X86_INS_AND, arch, ctx, acc, src, acc_op.bits());
            break;
            
        case X86_INS_CMP:
            transfer_acc_src_arith(X86_INS_SUB, arch, ctx, acc, src, acc_op.bits());
            break;
            
        default:
            unimplemented("%s", I->mnemonic);
    }
    
    acc_op.write(arch, acc, write_out);
}

template <typename OutputIt1, typename OutputIt2>
void Inst::transfer_jcc(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const {
    const Operand op {I->detail->x86.operands[0]};
    const z3::expr taken = op.read(arch, read_out);
    const z3::expr not_taken = arch.eip + ctx.bv_val(I->size, 32);
    const z3::expr zero = ctx.bv_val(0, 1);
    const z3::expr one = ctx.bv_val(1, 1);
    using K = Condition::Kind;
    static const std::unordered_map<unsigned, Condition::Kind> cond_map = {
        {X86_INS_JE,  K::E},
        {X86_INS_JGE, K::GE},
        {X86_INS_JNE, K::NE},
        {X86_INS_JA,  K::A},
    };
    const Condition cond {cond_map.at(I->id)};
    
    arch.eip = z3::ite(cond(arch), taken, not_taken);
}

template <typename OutputIt1, typename OutputIt2>
void Inst::transfer_cmovcc(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const {
    const Operand dst {x86->operands[0]};
    const Operand src {x86->operands[1]};
    using K = Condition::Kind;
    static const std::unordered_map<unsigned, Condition::Kind> cond_map = {
        {X86_INS_CMOVA, K::A},
    };
    const Condition cond {cond_map.at(I->id)};
    const z3::expr value = z3::ite(cond(arch), src.read(arch, read_out), dst.read(arch, read_out));
    dst.write(arch, value, write_out);
}

template <typename OutputIt1, typename OutputIt2>
void Inst::transfer_string(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const {
    switch (I->id) {
        case X86_INS_STOSD:
            arch.mem.write(arch.edi, arch.eax, write_out);
            arch.edi += 4;
            break;
        case X86_INS_MOVSB:
            arch.mem.write(arch.edi, arch.mem.read(arch.esi, 4, read_out), write_out);
            arch.esi += 4;
            arch.edi += 4;
            break;
        default:
            unimplemented("string %s", I->mnemonic);
    }
}

template <typename OutputIt1, typename OutputIt2>
void Inst::transfer_string_rep(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const {
    switch (x86->prefix[0]) {
        case X86_PREFIX_REP:
            transfer_string(arch, ctx, read_out, write_out);
            arch.ecx -= 1;
            arch.eip = z3::ite(arch.ecx == 0, arch.eip + I->size, arch.eip);
            break;
        default: unimplemented("prefix %02hhx", x86->prefix[0]);
    }
}

template <typename OutputIt1, typename OutputIt2>
void Inst::transfer_shift(ArchState& arch, z3::context& ctx, OutputIt1 read_out, OutputIt2 write_out) const {
    assert(x86->op_count == 2);
    const Operand acc_op {x86->operands[0]};
    const Operand shift_op {x86->operands[1]};
    const z3::expr acc = acc_op.read(arch, read_out);
    z3::expr shift = shift_op.read(arch, read_out);
    assert(acc.get_sort().bv_size() >= shift.get_sort().bv_size());
    shift = z3::zext(shift, acc.get_sort().bv_size() - shift.get_sort().bv_size());
    z3::expr res {ctx};
    z3::expr cf {ctx};
    struct Shift {
        z3::expr (*f)(const z3::expr&, const z3::expr&);
        unsigned bit;
    };
    static const std::unordered_map<unsigned, Shift> map = {
        {X86_INS_SHR, {&z3::lshr, 0}},
    };
    const Shift& info = map.at(I->id);
    arch.cf = info.f(acc, shift - 1).extract(info.bit, info.bit);
    acc_op.write(arch, info.f(acc, shift), write_out);
}


std::ostream& operator<<(std::ostream& os, const ArchState& arch) {
#define ENT(name, ...) os << #name << ": " << arch.name.simplify() << "\n";
    X_x86_REGS(ENT, ENT);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
    return os;
}


MemState::MemState(z3::context& ctx, const Sort& sort): ctx(ctx), mem(ctx) {
    mem = ctx.constant("mem", ctx.array_sort(ctx.bv_sort(32 - 2), ctx.bv_sort(32)));
}

template <typename OutputIt>
z3::expr MemState::read(const z3::expr& address, unsigned size, OutputIt read_out) const {
    // TODO: For now, assumed aligned accesses.
    z3::context& ctx = address.ctx();
    z3::expr addr_hi = address.extract(31, 2);
    z3::expr dword = mem[addr_hi];
    
    *read_out++ = Read {address, dword};
    
    switch (size) {
        case 4:
            // solver.add(address.extract(1, 0) == address.ctx().bv_val(0, 2));
            return dword;
            
        case 2:
            // solver.add(address.extract(0, 0) == address.ctx().bv_val(0, 1));
            return z3::ite(address.extract(2, 2) == ctx.bv_val(0, 1), dword.extract(15, 0), dword.extract(31, 16));
            
        case 1: {
            const z3::expr idx = address.extract(1, 0);
            z3::expr res {ctx};
            for (unsigned i = 0; i < 4; ++i) {
                const z3::expr cmp_idx = ctx.bv_val(i, 2);
                const z3::expr cmp = (idx == cmp_idx);
                unsigned hi = (i + 1) * 8 - 1;
                unsigned lo = i * 8;
                z3::expr byte = dword.extract(hi, lo);
                if (i == 0) {
                    res = dword.extract(hi, lo);
                } else {
                    res = z3::ite(cmp, byte, res);
                }
            }
            return res;
        }
            
        default: std::abort();
    }
}


z3::expr Register::read(const ArchState& arch) const {
    switch (reg) {
        case X86_REG_EAX: return arch.eax;
        case X86_REG_EBX: return arch.ebx;
        case X86_REG_ECX: return arch.ecx;
        case X86_REG_EDX: return arch.edx;
            
        case X86_REG_EDI: return arch.edi;
        case X86_REG_ESI: return arch.esi;
            
        case X86_REG_EBP: return arch.ebp;
        case X86_REG_ESP: return arch.esp;
            
        case X86_REG_CL: return arch.ecx.extract(7, 0);
            
        default:
            unimplemented("reg %s", cs_reg_name(g_handle, reg));
    }
}

void Register::write(ArchState& arch, const z3::expr& e) const {
    switch (reg) {
        case X86_REG_EAX: arch.eax = e; break;
        case X86_REG_EBX: arch.ebx = e; break;
        case X86_REG_ECX: arch.ecx = e; break;
        case X86_REG_EDX: arch.edx = e; break;
            
        case X86_REG_EDI: arch.edi = e; break;
        case X86_REG_ESI: arch.esi = e; break;
            
        case X86_REG_EBP: arch.ebp = e; break;
        case X86_REG_ESP: arch.esp = e; break;
            
        default:
            unimplemented("reg %s", cs_reg_name(g_handle, reg));
    }
}

template <typename OutputIt>
void MemState::write(const z3::expr& address, const z3::expr& value, OutputIt write_out) {
    const unsigned size = value.get_sort().bv_size() / 8;
    const z3::expr addr_hi = address.extract(31, 2);
    const z3::expr addr_lo = address.extract(1, 0);
    z3::expr dword = mem[addr_hi];
    
    switch (size) {
        case 4:
            dword = value;
            break;
            
        case 2: {
            dword = z3::ite(addr_lo.extract(1, 1) == 0, z3::concat(dword.extract(31, 16), value), z3::concat(value, dword.extract(15, 0)));
            // solver.add(addr_lo.extract(0, 0) == ctx.bv_val(0, 1));
            break;
        }
            
        case 1: {
            dword = z3::ite(addr_lo == 0, z3::concat(dword.extract(31, 8), value),
                            z3::ite(addr_lo == 1, z3::concat(dword.extract(31, 16), value, dword.extract(7, 0)),
                                    z3::ite(addr_lo == 2, z3::concat(dword.extract(31, 24), value, dword.extract(15, 0)),
                                            z3::concat(value, dword.extract(23, 0)))));
            break;
        }
            
    }
    mem = z3::store(mem, addr_hi, dword);
    *write_out++ = Write {address, dword};
 }


#define ENT_(name, ...) name(ctx)
#define ENT(name, ...) ENT_(name),
ArchState::ArchState(z3::context& ctx, const Sort& sort):
X_x86_REGS(ENT, ENT_), X_x86_FLAGS(ENT, ENT_), mem(ctx, sort.mem) {
    zero();
}
#undef ENT_
#undef ENT

void ArchState::create(unsigned id) {
#define ENT(name) name = name.ctx().bv_const((std::string(#name) + std::to_string(id)).c_str(), 32);
    X_x86_REGS(ENT, ENT);
#undef ENT
#define ENT(name, ...) name = name.ctx().bv_const((std::string(#name) + std::to_string(id)).c_str(), 1);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
}

z3::expr ArchState::operator==(const ArchState& other) const {
#define ENT_(name, ...) name == other.name
#define ENT(name, ...) ENT_(name) &&
    return X_x86_REGS(ENT, ENT_) && X_x86_FLAGS(ENT, ENT_);
#undef ENT
#undef ENT_
}

void Context::explore_paths_rec_dst(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask) {
    while (true) {
        const z3::check_result res = solver.check();
        if (res != z3::sat) {
            break;
        }
        const z3::model model = solver.get_model();
        const z3::expr eip = model.eval(out_arch.eip);
        std::cerr << "dst " << eip << "\n";
        solver.push();
        {
            solver.add(eip == out_arch.eip);
            explore_paths_rec(program, out_arch, solver, eip.as_uint64(), write_mask);
        }
        solver.pop();
        solver.add(eip != out_arch.eip);
    }
}

void Context::explore_paths_rec_read(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const ReadVec& reads, const WriteVec& writes, ReadVec::const_iterator read_it) {
    
    if (read_it == reads.end()) {
        explore_paths_rec_write(program, in_arch, out_arch, solver, write_mask, writes, writes.begin());
        return;
    }
    
    const auto& sym_read = *read_it;
    unsigned n = 0;
    
    while (true) {
        const z3::check_result res = solver.check();
        if (res != z3::sat) {
            break;
        }
        const z3::model model = solver.get_model();

        MemState::Read con_read = sym_read.eval(model);
        const auto olddata = con_read.data;
        con_read.data = model.eval(con_read(core, write_mask));
        
        std::cerr << "read " << con_read.addr << " " << con_read.data << " (" << olddata << ")\n";
        
        solver.push();
        {
            solver.add(con_read == sym_read);
            explore_paths_rec_read(program, in_arch, out_arch, solver, write_mask, reads, writes, std::next(read_it));
        }
        solver.pop();
        solver.add(con_read.addr != sym_read.addr);
    }
}

void Context::explore_paths_rec_write(Program& program, const ArchState& in_arch, const ArchState& out_arch, z3::solver& solver, const ByteMap& write_mask, const WriteVec& writes, WriteVec::const_iterator write_it) {
    if (write_it == writes.end()) {
        explore_paths_rec_dst(program, in_arch, out_arch, solver, write_mask);
        return;
    }
    
    const auto& sym_write = *write_it;

    while (true) {
        const z3::check_result res = solver.check();
        if (res != z3::sat) {
            break;
        }
        const z3::model model = solver.get_model();
        MemState::Write con_write = sym_write.eval(model);
        std::cerr << "write " << con_write.addr << " " << con_write.data << "\n";
        
        solver.push();
        {
            solver.add(con_write.addr == sym_write.addr);
            ByteMap new_write_mask = write_mask;
            for (std::size_t i = 0; i < sym_write.size(); ++i) {
                new_write_mask.insert(con_write.addr.as_uint64() + i);
            }
            explore_paths_rec_write(program, in_arch, out_arch, solver, new_write_mask, writes, std::next(write_it));
        }
        solver.pop();
        
        solver.add(sym_write.addr != con_write.addr);
    }
}

void Context::explore_paths_rec(Program& program, const ArchState& in_arch, z3::solver& solver, addr_t addr, ByteMap write_mask) {
    // add instructions until branch
    
    if (program.map.find(addr) == program.map.end()) {
        // find address in core
        const auto seg_it = std::find_if(core.segments_begin(), core.segments_end(), [&] (const cores::Segment& seg) {
            return seg.contains(addr, 1);
        });
        if (seg_it == core.segments_end()) {
            std::cerr << "jump outside of address space: " << std::hex << addr << "\n";
            dump_trace("trace.asm", trace);
            return;
        }
        // TODO: make this safer
        const void *data = seg_it->at(addr);
        program.disasm((const uint8_t *) data, 16, addr, 1);
    }
    
    const Inst& inst = program.map.at(addr);
    
    trace.push_back(inst.I);
    
    ArchState arch = in_arch;
    ReadVec reads;
    WriteVec writes;
    inst.transfer(arch, std::back_inserter(reads), std::back_inserter(writes));
    ArchState out_arch = arch;
    out_arch.create(next_id++);
    solver.add(out_arch == arch);
    
    std::cerr << "inst @ " << std::hex << addr << " : "  << inst.I->mnemonic << " " << inst.I->op_str << "\n";
    
    explore_paths_rec_read(program, in_arch, out_arch, solver, write_mask, reads, writes, reads.begin());
    
    trace.pop_back();
}

void Context::explore_paths(Program& program) {
    z3::solver solver {ctx};
    ArchState in_arch {ctx, arch_sort};
    
    const cores::Thread& thd = core.thread(0);
    assert(thd.flavor == x86_THREAD_STATE32);
    
    x86_thread_state32_t state = * (const x86_thread_state32_t *) thd.data;
    
    std::cerr << "eip = " << std::hex << state.__eip << "\n";
    
#define ENT(name) in_arch.name = ctx.bv_val(state.__##name, 32);
    X_x86_REGS(ENT, ENT);
#undef ENT
#define ENT(name, bit) in_arch.name = ctx.bv_val((state.__eflags >> bit) & 1, 1);
    X_x86_FLAGS(ENT, ENT);
#undef ENT
        
    ByteMap write_mask;
    for (const auto& range : symbolic_ranges) {
        for (uint64_t addr = range.base; addr < range.base + range.len; ++addr) {
            write_mask.insert(addr);
        }
    }
    
    // set return address
    in_arch.mem.write(in_arch.esp, ctx.bv_val(0x42424242, 32), util::null_output_iterator());
    for (uint64_t i = 0; i < 4; ++i) {
        write_mask.insert(in_arch.esp.as_uint64() + i);
    }
    
    auto e = in_arch.mem.read(in_arch.esp, 4, util::null_output_iterator());
    solver.push();
    solver.add(e != 0x42424242);
    assert(solver.check() == z3::unsat);
    solver.pop();
    
    explore_paths_rec(program, in_arch, solver, state.__eip, write_mask);
}

std::ostream& dump_trace(std::ostream& os, const std::vector<const cs_insn *>& trace) {
    for (const cs_insn *I : trace) {
        os << std::hex << I->address << ": " << I->mnemonic << " " << I->op_str << "\n";
    }
    return os;
}

void dump_trace(const std::string& path, const std::vector<const cs_insn *>& trace) {
    std::ofstream ofs {path};
    dump_trace(ofs, trace);
}

}
