#pragma once

#include <string>
#include <exception>
#include <cstring>
#include <vector>

#include <capstone/capstone.h>

namespace cs {

  class exception: public std::exception {
  public:
    exception(cs_err err): std::exception(), err(err) {}
    virtual const char *what() const noexcept override { return cs_strerror(err); }
  private:
    cs_err err;
  };

#if 0
  class insn {
  public:
    insn(cs_insn *insn_): insn_(insn_) {}
    
    cs_insn *get_insn() const { return insn_; }
    uint64_t& address() { return insn_->address; }
    const uint64_t& address() const { return insn_->address; }

    cs_detail *detail() const { return insn_->detail; }
    unsigned id() const { return insn_->id; }

  private:
    cs_insn *insn_ = nullptr;
  };
#endif
  
  class insns {
  public:
    using value_type = cs_insn;
  private:
    using Vec = std::vector<value_type>;
  public:
    using iterator = value_type *;
    using const_iterator = const value_type *;
    
    insns(): vec(nullptr), count(0) {}
    ~insns() { cs_free(vec, count); }

    insns(const insns&) = delete;
    insns(insns&& other) {
      vec = other.vec;
      other.vec = nullptr;
      count = other.count;
      other.count = 0;
    }

    value_type& operator[](std::size_t idx) { return vec[idx]; }
    const value_type& operator[](std::size_t idx) const { return vec[idx]; }
    value_type& at(std::size_t idx) {
      if (idx >= count) {
	throw std::out_of_range(std::to_string(idx));
      }
      return vec[idx];
    }
    const value_type& at(std::size_t idx) const {
      if (idx >= count) {
	throw std::out_of_range(std::to_string(idx));
      }
      return vec[idx];
    }
    
    std::size_t size() const { return count; }
    iterator begin() { return vec; }
    const_iterator begin() const { return vec; }
    iterator end() { return vec + count; }
    const_iterator end() const { return vec + count; }
    value_type *data() { return vec; }
    const value_type *data() const { return vec; }

  private:
    value_type *vec;
    std::size_t count;

    friend class handle;
  };

  class handle {
  public:
    handle(cs_arch arch, cs_mode mode) {
      const cs_err err = cs_open(arch, mode, &handle_);
      if (err != CS_ERR_OK) {
	throw exception(err);
      }
    }

    ~handle() { cs_close(&handle_); }

    csh& get_handle() { return handle_; }
    const csh get_handle() const { return handle_; }

    std::size_t disasm(const uint8_t *code, std::size_t code_size, uint64_t address, std::size_t count, insns& res) {
      return res.count = cs_disasm(handle_, code, code_size, address, count, &res.vec);
    }

    template <typename Container>
    std::size_t disasm(const Container& container, uint64_t address, std::size_t count, insns& res) {
      return disasm(container.data(), container.size() * sizeof(container.data()[0]),
		    address, count, res);
    }

    void option(cs_opt_type type, std::size_t value) {
      const cs_err err = cs_option(handle_, type, value);
      if (err != CS_ERR_OK) {
	throw exception(err);
      }
    }

    void detail(bool on) {
      option(CS_OPT_DETAIL, on ? CS_OPT_ON : CS_OPT_OFF);
    }
    
  private:
    csh handle_;
  };
  
  
}
