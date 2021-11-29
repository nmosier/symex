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


struct AddrSet2 {
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
    
    bool contains(value_type x) const {
        const auto it = map.find(key(x));
        if (it == map.end()) {
            return false;
        } else {
            return it->second[value(x)];
        }
    }
    
    void erase(value_type x) {
        const auto it = map.find(key(x));
        if (it != map.end()) {
            it->second[value(x)] = false;
        }
    }
    
private:
    
    static value_type key(value_type x) {
        return x & ~pagemask;
    }
    static value_type value(value_type x) {
        return x & pagemask;
    }
};


#if 0
template <class T>
struct AddrMap2 {
    static inline constexpr uint64_t pagesize = 4096;
    static inline constexpr uint64_t pagemask = pagesize - 1;
    
    using key_type = uint64_t;
    using mapped_type = T;
    
    using Array = std::array<std::optional<z3::expr>, pagesize>;
    using Map = std::unordered_map<key_type, Array>;
    
    Map map;
    
    std::optional<z3::expr> find(key_type x) const {
        const auto it = map.find(key(x));
        if (it == map.end()) {
            return std::nullopt;
        } else {
            return it->second[value(x)];
        }
    }
    
    void insert_or_assign(key_type key, const mapped_type& value) {
        map[this->key(key)][this->value(key)] = value;
    }
    
private:
    
    static key_type key(key_type x) {
        return x & ~pagemask;
    }
    static key_type value(key_type x) {
        return x & pagemask;
    }
};
#else
template <class T>
struct AddrMap2 {
    static inline constexpr uint64_t pagesize = 4096;
    static inline constexpr uint64_t pagemask = pagesize - 1;
    
    using key_type = uint64_t;
    using mapped_type = T;
    
    using Submap = std::unordered_map<key_type, mapped_type>;
    using Map = std::unordered_map<key_type, Submap>;
    Map map;
    
    std::optional<z3::expr> find(key_type x) const {
        const auto it = map.find(key(x));
        if (it == map.end()) {
            return std::nullopt;
        } else {
            const auto it2 = it->second.find(value(x));
            if (it2 == it->second.end()) {
                return std::nullopt;
            } else {
                return it2->second;
            }
        }
    }
    
    void insert_or_assign(key_type key, const mapped_type& value) {
        const auto res = map.emplace(this->key(key), Submap());
        if (res.second) {
            res.first->second.reserve(pagesize);
        }
        res.first->second.insert_or_assign(this->value(key), value);
    }
    
private:
    
    static key_type key(key_type x) {
        return x & ~pagemask;
    }
    static key_type value(key_type x) {
        return x & pagemask;
    }
};
#endif


struct MemState {
    cores::Core& core;
    using Map = std::unordered_map<uint64_t, z3::expr>;
    Map con_mem;
    z3::expr sym_mem;
#if 1
    using AddrSet2 = std::unordered_set<uint64_t>;
#endif
    AddrSet2 init;
    AddrSet2 sym_writes;
    AddrSet2 uncommitted_writes;
    
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
    z3::expr read_byte(const z3::expr& sym_addr, const std::vector<z3::expr>& con_addrs);
    void write_byte(const z3::expr& sym_addr, const std::vector<z3::expr>& con_addrs, const z3::expr& sym_data);
    void check() const;
};


}
