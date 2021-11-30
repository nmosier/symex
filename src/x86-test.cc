#include <vector>
#include <cstdint>
#include <unistd.h>
#define _XOPEN_SOURCE
#include <mach/i386/processor_info.h>
#include <mach/i386/_structs.h>
#include <i386/_mcontext.h>
#include <ucontext.h>
#include <mach/i386/thread_status.h>

#include "x86.h"
#include "program.h"
#include "context.h"
#include "config.h"

csh g_handle;

const char *prog;

#define error(...) \
do { \
fprintf(stderr, "%s: error: ", prog); \
fprintf(stderr, __VA_ARGS__); \
fprintf(stderr, "\n"); \
std::exit(1); \
} while (false)

void usage(FILE *f = stderr) {
    const char *s = R"=(usage: %s [option...] <core>
Options:
 -h               show help
 -s <addr>,<len>  make memory range symbolic
 -e <entrypoint>  override entrypoint (eip)
 -j <threads>     maximum number of threads to use
)=";
    fprintf(f, s, prog);
}

uint64_t parse_uint64(const char *s) {
    char *end;
    const uint64_t res = std::strtoull(s, &end, 0);
    if (*s == '\0' || *end != '\0') {
        error("bad uint64 %s", s);
    }
    return res;
}

int main(int argc, char *argv[]) {
    prog = argv[0];
    
    int optc;
    while ((optc = getopt(argc, argv, "hs:e:j:")) >= 0) {
        switch (optc) {
            case 'h':
                usage(stdout);
                return EXIT_SUCCESS;
                
            case 's': {
                const char *base_s = strsep(&optarg, ",");
                const char *len_s = optarg;
                char *end;
                x86::MemoryRange range;
                range.base = parse_uint64(base_s);
                range.len = parse_uint64(len_s);
                conf::symbolic_ranges.push_back(range);
                conf::deterministic = false;
                break;
            }
                
            case 'e': {
                char *end;
                conf::entrypoint = std::strtoul(optarg, &end, 0);
                if (*optarg == '\0' || *end != '\0') {
                    std::cerr << prog << ": -e: bad argument\n";
                    return EXIT_FAILURE;
                }       
                break;
            }
                
            case 'j': {
                conf::pool.open(std::stoul(optarg));
                break;
            }
                
            default:
                usage();
                return EXIT_FAILURE;
        }
    }
    
    if (argc - optind != 1) {
        usage();
        return EXIT_FAILURE;
    }
    
    const char *core = argv[optind++];
    
    x86::Program program;
    g_handle = program.handle.get_handle();
    
    x86::Context ctx {core};
    ctx.symbolic_ranges = conf::symbolic_ranges;
    
    assert(ctx.core.thread(0).flavor == x86_THREAD_STATE32);
    
    std::cerr << ctx.core.nsegments() << " segments\n";
    
    ctx.explore_paths();
    
}
