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
    
    const Thread& thread(std::size_t idx) const { return threads_.at(idx); }
    std::size_t nthreads() const { return threads_.size(); }
    
private:
    std::vector<Thread> threads_;
    
    void handle_segment(const segment_command *seg);
    void handle_thread(const thread_command *thd);
};

}
