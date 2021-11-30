#include "memstate.h"
#include "util.h"
#include "exception.h"

namespace x86 {

z3::expr MemState::get_init_mem(z3::context& ctx) {
    return ctx.constant("mem", ctx.array_sort(ctx.bv_sort(32), ctx.bv_sort(8)));
}

MemState::MemState(z3::context& ctx, cores::Core& core): core(core), sym_mem(ctx) {
    sym_mem = get_init_mem(ctx);
}

/* INVARIANTS:
 * - sym_writes holds the set of addresses that may have been symbolically written to.
 * - uncommitted_writes holds the set of addresses that have been concretely but not symbolically written to.
 * sym_writes and uncommitted_writes must not intersect.
 *
 */

void MemState::check() const {
    /* check that uncommitted writes subset of keys in con_mem */
    for (const auto key : uncommitted_writes) {
        assert(con_mem.contains(key));
    }

}

z3::expr MemState::read_byte(const z3::expr& sym_addr, const std::vector<z3::expr>& con_addrs) {
    check();
    const auto chk = util::defer([&] () { check(); });
    assert(!con_addrs.empty());
    
    /* check if any access in symbolic ranges. If so, use sym_mem */
    for (const z3::expr& con_addr : con_addrs) {
        const uint64_t int_addr = con_addr.get_numeral_uint64();
        if (sym_writes.contains(int_addr)) {
            return sym_mem[con_addr];
        }
    }
    
    /* check if the address of this read can be concretized */
    if (con_addrs.size() == 1) {
        
        const z3::expr& con_addr = con_addrs.front();
        const uint64_t int_addr = con_addr.get_numeral_uint64();
        const auto con_mem_it = con_mem.find(int_addr);
        
        if (con_mem_it == con_mem.end()) {
            
            /* read from core */
            return ctx().bv_val(core_read(int_addr), 8);
            
        } else {
            
            /* read from concrete memory */
            return con_mem_it->second;
            
        }
        
    } else {
        
        std::cerr << "SYMBOLIC-READ:";
        for (const z3::expr& con_addr : con_addrs) {
            std::cerr << " " << con_addr;
        }
        std::cerr << "\n";
        
        /* read is symbolic: can source many locations */
        return sym_mem[sym_addr];
        
    }
}

void MemState::write_byte(const z3::expr& sym_addr, const std::vector<z3::expr>& con_addrs, const z3::expr& sym_data) {
    check();
    const auto chk = util::defer([&] () { check(); });
    assert(!con_addrs.empty());
    
    /* check if write address can be concretized */
    if (con_addrs.size() == 1) {
        
        const z3::expr& con_addr = con_addrs.front();
        const uint64_t int_addr = con_addr.get_numeral_uint64();
        
        /* update concrete memory */
        con_mem.insert_or_assign(int_addr, sym_data);
        
        /* update symbolic write mask */
        sym_writes.erase(int_addr);
        
        /* update uncommitted write mask */
        uncommitted_writes.insert(int_addr);
        
        /* update initialization mask */
        init.insert(int_addr);
        
    } else {
        
        std::cerr << "SYMBOLIC-WRITE\n";
        
        /* commit write(s) if necessary and add to symbolic mask */
        for (const z3::expr& con_addr : con_addrs) {
            const uint64_t int_addr = con_addr.get_numeral_uint64();
            if (uncommitted_writes.erase(int_addr)) {
                /* commit write from con_mem to sym_mem */
                const auto con_mem_it = con_mem.find(int_addr);
                assert(con_mem_it != con_mem.end());
                sym_mem = z3::store(sym_mem, con_addr, con_mem_it->second);
                con_mem.erase(con_mem_it);
            } else if (init.insert(int_addr).second) {
                /* initialize write in sym_mem */
                const uint8_t con_data = core_read(int_addr);
                const z3::expr sym_data = ctx().bv_val(con_data, 8);
                sym_mem = z3::store(sym_mem, con_addr, sym_data);
            }
            sym_writes.insert(int_addr);
        }
        
        /* update symbolic memory */
        sym_mem = z3::store(sym_mem, sym_addr, sym_data);
        
    }
    
}

uint8_t MemState::core_read(uint64_t addr) const {
    if (const auto data = core.try_read<uint8_t>(addr)) {
        return *data;
    } else {
        throw segfault(ctx().bv_val(addr, 32));
    }
}

z3::expr MemState::read(const z3::expr &sym_addr, unsigned size, z3::solver& solver) {
    // const auto con_addrs = initialize(sym_addr, size, solver);
    std::vector<z3::expr> con_addrs;
    z3::enumerate(solver, sym_addr, std::back_inserter(con_addrs));
    
    /* perform read */
    std::vector<z3::expr> little;
    for (unsigned i = 0; i < size; ++i) {
        const z3::expr sym_addr_i = sym_addr + ctx().bv_val(i, 32);
        std::vector<z3::expr> con_addrs_i;
        std::transform(con_addrs.begin(), con_addrs.end(), std::back_inserter(con_addrs_i), [&] (const z3::expr& con_addr) -> z3::expr {
            const uint64_t int_addr_i = con_addr.get_numeral_uint64() + i;
            return ctx().bv_val(int_addr_i, 32);
        });
        const z3::expr sym_data = read_byte(sym_addr_i, con_addrs_i);
        little.push_back(sym_data);
    }
    const z3::expr res = z3::concat(little.rbegin(), little.rend());
    
    return res;
}

void MemState::write(const z3::expr& sym_addr, const z3::expr& value, z3::solver& solver) {
    const unsigned bits = value.get_sort().bv_size();
    const unsigned size = bits / 8;
    
    // const auto con_addrs = initialize(sym_addr, size, solver);
    std::vector<z3::expr> con_addrs;
    z3::enumerate(solver, sym_addr, std::back_inserter(con_addrs));
    
    /* perform write */
    for (unsigned i = 0; i < size; ++i) {
        const z3::expr sym_addr_i = sym_addr + ctx().bv_val(i, 32);
        std::vector<z3::expr> con_addrs_i;
        std::transform(con_addrs.begin(), con_addrs.end(), std::back_inserter(con_addrs_i), [&] (const z3::expr& con_addr) -> z3::expr {
            const uint64_t int_addr_i = con_addr.get_numeral_uint64() + i;
            return ctx().bv_val(int_addr_i, 32);
        });
        const z3::expr sym_data_i = value.extract((i + 1) * 8 - 1, i * 8);
        
        write_byte(sym_addr_i, con_addrs_i, sym_data_i);
        // sym_mem = z3::store(sym_mem, sym_addr + ctx().bv_val(i, 32), value.extract((i + 1) * 8 - 1, i * 8));
    }
}

void MemState::symbolic(uint64_t begin, uint64_t end) {
    for (uint64_t it = begin; it != end; ++it) {
        const z3::expr addr = ctx().bv_val(it, 32);
        const z3::expr data = sym_mem[addr];
        con_mem.insert_or_assign(it, data);
        init.insert(it);
    }
}

}
