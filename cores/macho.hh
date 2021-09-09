#pragma once

#include "core.hh"

namespace cores {

  /* Mach-O Core Dump */
  class MachOCore: public Core {
  public:
    template <typename... Args>
    MachOCore(Args&&... args): Core(std::forward<Args>(args)...) {}

    virtual void parse() override;

    static Core *Create(const char *path) {
      return new MachOCore(path);
    }
  
  private:

    void handle_segment(const segment_command *seg);
  };

}
