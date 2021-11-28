#pragma once

#include <unordered_set>
#include <unordered_map>
#include <map>

#include <z3++.h>

#include "x86.h"
#include "cores/macho.hh"
#include "util.h"

namespace x86 {

#if 0
struct MemState {
    z3::context *ctx_;
    z3::expr mem;
    
    z3::context& ctx() const { return *ctx_; }
    
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
        
        void transform_expr(std::function<z3::expr (const z3::expr&)> f) {
            addr = f(addr);
            data = f(data);
        }
        
        void substitute(const z3::expr_vector& src, const z3::expr_vector& dst) {
            transform_expr([&src, &dst] (z3::expr e) -> z3::expr {
                return e.substitute(src, dst);
            });
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
    
    MemState(z3::context& ctx);

    template <typename OutputIt>
    z3::expr read(const z3::expr& address, unsigned size, OutputIt read_out) const;
    
    template <typename OutputIt>
    void write(const z3::expr& address, const z3::expr& value, OutputIt write_out);
    
    static z3::expr get_init_mem(z3::context& ctx) {
        return ctx.constant("mem", ctx.array_sort(ctx.bv_sort(32), ctx.bv_sort(8)));
    }
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
#endif


struct Mask {
    static inline constexpr uint64_t pagesize = 4096;
    static inline constexpr uint64_t pagemask = pagesize - 1;
    
    using value_type = uint64_t;
    
    using Map = std::unordered_map<value_type, std::array<bool, pagesize>>;
    Map map;
    
    bool insert(value_type x) {
        bool& b = map[key(x)][value(x)];
        const bool res = b;
        b = true;
        return res;
    }
    
private:
    
    static value_type key(value_type x) {
        return x & ~pagemask;
    }
    static value_type value(value_type x) {
        return x & pagemask;
    }
};



struct MemState {
    cores::Core& core;
    using Map = std::unordered_map<uint64_t, z3::expr>;
    Map con_mem;
    z3::expr sym_mem;
#if 0
    using Mask = std::unordered_set<uint64_t>;
#endif
    Mask init;
    Mask sym_writes;
    
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
        
        void transform_expr(std::function<z3::expr (const z3::expr&)> f) {
            addr = f(addr);
            data = f(data);
        }
        
        void substitute(const z3::expr_vector& src, const z3::expr_vector& dst) {
            transform_expr([&src, &dst] (z3::expr e) -> z3::expr {
                return e.substitute(src, dst);
            });
        }
    };
    
    struct Read: Access {
        Read eval(const z3::model& model) const { return Read {Access::eval(model)}; }
    };
    
    struct Write: Access {
        Write eval(const z3::model& model) const { return Write {Access::eval(model)}; }
    };
    
    
    MemState(z3::context& ctx, cores::Core& core);
    
    z3::context& ctx() const {
        return sym_mem.ctx();
    }
    
    z3::expr read(const z3::expr& addr, unsigned size, z3::solver& solver);
    void write(const z3::expr& addr, const z3::expr& value, z3::solver& solver);
    void symbolic(uint64_t begin, uint64_t end);
    
    static z3::expr get_init_mem(z3::context& ctx);
    
private:
    std::vector<z3::expr> initialize(const z3::expr& sym_addr, unsigned size, z3::solver& solver);
    
    z3::expr read_byte(const z3::expr& sym_addr, const std::vector<z3::expr>& con_addrs);
    void write_byte(const z3::expr& sym_addr, const std::vector<z3::expr>& con_addrs, const z3::expr& sym_data);
};


}
