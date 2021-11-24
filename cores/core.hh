#pragma once

#include <vector>
#include <stdexcept>
#include <mach-o/loader.h>
#include <string>
#include <cassert>
#include <optional>

#include "file.hh"
#include "prot.hh"

namespace cores {

  struct Segment {
    using ptr_t = uint64_t;
  
    ptr_t vmaddr;
    const void *base;
    size_t len;
    prot_t prot; // mask of READ, WRITE, EXEC

    Segment(ptr_t vmaddr, const void *base, size_t len, prot_t prot):
      vmaddr(vmaddr), base(base), len(len), prot(prot) {}

    bool contains(ptr_t dataptr, size_t datalen) const {
      return vmaddr <= dataptr && dataptr + datalen < vmaddr + len;
    }
  
    const void *at(ptr_t addr) const {
      return (const char *) base + (addr - vmaddr);
    }
  };

struct Thread {
    uint32_t flavor;
    uint32_t count;
    const void *data;
    
    std::size_t size() const { return count * sizeof(uint32_t); }
};

  /* An abstract core dump. */
  class Core {
  public:
    using Segments = std::vector<Segment>;
    using SegmentIterator = Segments::const_iterator;
    struct ParseError: std::invalid_argument {
      ParseError(const char *msg): std::invalid_argument(msg) {}
    };

    const File& file() const { return file_; }

    virtual void parse() = 0;

    size_t nsegments() const { return segments_.size(); }
    SegmentIterator segments_begin() const { return segments_.begin(); }
    SegmentIterator segments_end() const { return segments_.end(); }
    const Segment& segment(size_t idx) const { return segments_.at(idx); }
      
      
      template <typename T>
      T read(uint64_t addr) const;
      
      template <typename T>
      std::optional<T> try_read(uint64_t addr) const;

    template <typename... Args>
    Core(Args&&... args): file_(std::forward<Args>(args)...) {}
    virtual ~Core() {}

    typedef Core *Create_t(const char *);
    static Core *Create(const char *path);

    static Create_t *Creator(const char *s);

  protected:
    File file_;
    Segments segments_;

    template <typename... Args>
    void segment_register(Args&&... args) {
      segments_.emplace_back(std::forward<Args>(args)...);
    }

    template <typename T>
    const T *at(size_t off) {
      return (const T *) ((const char *) file().map + off);
    }
  };

template <typename T>
std::optional<T> Core::try_read(uint64_t addr) const {
    for (auto it = segments_begin(); it != segments_end(); ++it) {
        if (it->contains(addr, sizeof(T))) {
            return * (const T *) ((const uint8_t *) it->base + (addr - it->vmaddr));
        }
    }
    return std::nullopt;
}

template <typename T>
T Core::read(uint64_t addr) const {
    if (const auto res = try_read<T>(addr)) {
        return *res;
    } else {
        throw std::out_of_range("Core::read: invalid address");
    }
}

}
