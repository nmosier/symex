#include <cstdio>

#include "context.h"
#include "util.h"
#include "archstate.h"

namespace x86 {

void Context::check_accesses(const ReadVec& reads, const WriteVec& writes, z3::solver& solver) {
    for (const auto& read : reads) {
        if (solver.check() != z3::sat) { return; }
        const z3::model model = solver.get_model();
        z3::scope scope {solver};
        solver.add(read.addr != model.eval(read.addr));
        if (solver.check() == z3::sat) {
            report("read at %p has multiple source addresses", (void *) model.eval(read.addr).get_numeral_uint64());
        }
    }
    
    for (const auto& write : writes) {
        if (solver.check() != z3::sat) { return; }
        const z3::model model = solver.get_model();
        z3::scope scope {solver};
        solver.add(write.addr != model.eval(write.addr));
        if (solver.check() == z3::sat) {
            report("write at %p has multiple destination addresses", (void *) model.eval(write.addr).get_numeral_uint64());
        }
    }
}

void Context::check_operands(const Inst& I, const ArchState& arch, z3::solver& solver) {
    for (unsigned i = 0; i < I.x86->op_count; ++i) {
        const auto& operand = I.x86->operands[i];
        if (operand.type == X86_OP_MEM) {
            const MemoryOperand memop {operand.mem};
            if (memop.mem.index != X86_REG_INVALID) {
                const Register base {memop.mem.base};
                const Register index {memop.mem.index};
                const z3::expr addr = memop.addr(arch) - arch.ctx().bv_val(memop.mem.disp, 32);
                z3::scope scope {solver};
                solver.add(addr < base.read(arch) || addr < index.read(arch));
                if (solver.check() == z3::sat) {
                    report("array access underflow at %p", (void *) I.I->address);
                }
            }
        }
    }
}

void Context::check_regs(const ArchState& arch) {
    // esp should be constant
    if (!arch.esp.simplify().is_const()) {
        report("non-constant esp");
    }
}


void Symbols::add(const struct core &core) {
    struct symbol *symvec = NULL;
    ssize_t count;
    if ((count = core_symbols(&core, &symvec)) < 0) {
        core_perror("core_symbols");
        std::exit(EXIT_FAILURE);
    }
#if 0
    for (size_t i = 0; i < count; ++i) {
        map.emplace(symvec[i].vmaddr, symvec[i].name);
    }
#endif
    
#if 0
    int in[2];
    int out[2];
    if (::pipe(in) < 0 ||
        ::pipe(out) < 0) {
        std::perror("pipe");
        std::exit(EXIT_FAILURE);
    }
    
    const pid_t pid = ::fork();
    if (pid < 0) {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    } else if (pid == 0) {
        if (::dup2(in[0], STDIN_FILENO) < 0 ||
            ::dup2(out[1], STDOUT_FILENO) < 0) {
            std::perror("dup2");
        }
        ::execlp("c++filt", "c++filt", NULL);
        std::perror("execlp");
        std::exit(EXIT_FAILURE);
        
    }
        
    ::close(in[0]);
    ::close(out[1]);
    
    FILE *mangled;
    FILE *demangled;
    if ((mangled = ::fdopen(in[1], "w")) == NULL ||
        (demangled = ::fdopen(out[0], "r")) == NULL) {
        std::perror("fdopen");
        std::exit(EXIT_FAILURE);
    }
    
    for (size_t i = 0; i < count; ++i) {
        fprintf(mangled, "%s\n", symvec[i].name);
        fprintf(stderr, "here\n");
        fflush(mangled);
    }
    fflush(mangled);
    fclose(mangled);
    
    
    constexpr size_t buflen = 0x1000;
    char buf[buflen];
    for (size_t i = 0; i < count; ++i) {
        fprintf(stderr, "demangled %s\n", buf);

        if (std::fgets(buf, buflen, demangled) == NULL) {
            if (std::feof(demangled)) {
                std::cerr << "fgets: unexpected EOF\n";
            } else {
                std::perror("fgets");
            }
            std::exit(EXIT_FAILURE);
        }
        
                
        map.emplace(symvec[i].vmaddr, buf);
    }
        
    fclose(demangled);
    
#else
    
    FILE *f;
    if ((f = ::popen("c++filt", "r+")) == NULL) {
        std::perror("popen");
        std::exit(EXIT_FAILURE);
    }
    
    constexpr int buflen = 0x1000;
    char buf[buflen];
#if 0
    if (setlinebuf(f) < 0) {
        std::perror("setlinebuf");
        std::exit(EXIT_FAILURE);
    }
#endif
    for (size_t i = 0; i < count; ++i) {
        fprintf(f, "%s\n", symvec[i].name);
        fflush(f);
        
        if (fgets(buf, buflen, f) == NULL) {
            if (feof(f)) {
                std::cerr << "fscanf: unexpected EOF\n";
            } else {
                std::perror("fscanf");
            }
            std::abort();
        }
        if (char *p = strchr(buf, '\n')) {
            *p = '\0';
        }
        map.emplace(symvec[i].vmaddr, buf);
    }
    
    
#endif

}



}
