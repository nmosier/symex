#pragma once

#include <z3++.h>

#include "x86.h"
#include "cores/macho.hh"
#include "util.h"

namespace x86 {

struct MemState {
    z3::context& ctx;
    z3::expr mem;
    
    struct Access {
        z3::expr addr;
        z3::expr data;
        
        Access eval(const z3::model& model) const {
            return Access {model.eval(addr), model.eval(data)};
        }
        
        z3::context& ctx() const { return addr.ctx(); }
        unsigned bits() const { return data.get_sort().bv_size(); }
        std::size_t size() const { return bits() / 8; }
        
        z3::expr operator==(const Access& other) const {
            return addr == other.addr && data == other.data;
        }
        
        z3::expr operator!=(const Access& other) const {
            return !(*this == other);
        }
    };
    
    struct Read: Access {
        Read eval(const z3::model& model) const { return Read {Access::eval(model)}; }
        
        uint64_t operator()(const cores::Core& core) const;
        
        z3::expr operator()(const cores::Core& core, const ByteMap& write_mask) const;
    };
    
    struct Write: Access {
        Write eval(const z3::model& model) const { return Write {Access::eval(model)}; }
    };
    
#if 0
    struct Sort {
        z3::func_decl cons;
        z3::sort sort;
        z3::func_decl_vector projs;
        
        enum class Fields {
            XM_LIST(X_x86_MEMS)
        };
        
        Sort(z3::context& ctx): cons(ctx), sort(ctx), projs(ctx) {
            constexpr std::size_t size = 3;
            const char *names[size] = { XM_STR_LIST(X_x86_MEMS) };
            const auto memsort = [&] (unsigned bytes) -> z3::sort {
                return ctx.array_sort(ctx.bv_sort(32), ctx.bv_sort(bytes * 8));
            };
            const std::array<z3::sort, size> sorts = {memsort(1), memsort(2), memsort(4)};
            cons = ctx.tuple_sort("x86_mem", size, names, sorts.data(), projs);
            sort = cons.range();
        }
        
        MemState unpack(const z3::expr& e) const;
        z3::expr pack(MemState& mem) const;
    };
#endif
    
    MemState(z3::context& ctx);

    template <typename OutputIt>
    z3::expr read(const z3::expr& address, unsigned size, OutputIt read_out) const;
    
    template <typename OutputIt>
    void write(const z3::expr& address, const z3::expr& value, OutputIt write_out);
    
private:
    z3::expr read_aligned(const z3::expr& addr_hi, const z3::expr& addr_lo, unsigned size) const;
    z3::expr read_unaligned(const z3::expr& addr_hi, const z3::expr& addr_lo, unsigned size) const;
};

template <typename OutputIt>
z3::expr MemState::read(const z3::expr& address, unsigned size, OutputIt read_out) const {
    // TODO: For now, assumed aligned accesses.
    z3::context& ctx = address.ctx();
        
    std::vector<z3::expr> little;
    for (unsigned i = 0; i < size; ++i) {
        little.push_back(mem[address + ctx.bv_val(i, 32)]);
    }
    const z3::expr res = z3::concat(little.rbegin(), little.rend());
    
    *read_out++ = Read {address, res};
    return res;
}

template <typename OutputIt>
void MemState::write(const z3::expr& address, const z3::expr& value, OutputIt write_out) {
    z3::context& ctx = value.ctx();
    const unsigned bits = value.get_sort().bv_size();
    const unsigned size = bits / 8;
    for (unsigned i = 0; i < size; ++i) {
        mem = z3::store(mem, address + ctx.bv_val(i, 32), value.extract((i + 1) * 8 - 1, i * 8));
    }
    *write_out = Write {address, value};
 }


}
