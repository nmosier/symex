#include <array>

#include "macho.hh"

namespace cores {

void MachOCore::parse() {
    assert(file_.isopen());
    
    const mach_header *hdr = (const mach_header *) file_.map;
    
    if (hdr->magic != MH_MAGIC ||
        hdr->cputype != CPU_TYPE_X86
        ) {
        throw ParseError("not a valid Mach-O file");
    }
    
    if (hdr->filetype != MH_CORE) {
        throw ParseError("not a core dump");
    }
    
    /* parse commands */
    const load_command *lc = reinterpret_cast<const load_command *>(hdr + 1);
    for (size_t i = 0; i < hdr->ncmds; ++i) {
        switch (lc->cmd) {
            case LC_SEGMENT:
                handle_segment(reinterpret_cast<const segment_command *>(lc));
                break;
            case LC_THREAD:
            case LC_UNIXTHREAD:
                handle_thread(reinterpret_cast<const thread_command *>(lc));
                break;
        }
        lc = (const load_command *) ((const char *) lc + lc->cmdsize);
    }
}

void MachOCore::handle_segment(const segment_command *seg) {
    if (seg->initprot != VM_PROT_NONE) {
        const auto prot = seg->initprot;
        unsigned segprot = 0;
        constexpr std::array<std::pair<vm_prot_t, unsigned>, 3> prottab = {{
            std::make_pair(VM_PROT_READ, PROT::READ),
            std::make_pair(VM_PROT_WRITE, PROT::WRITE),
            std::make_pair(VM_PROT_EXECUTE, PROT::EXECUTE),
        }};
        for (const auto& entry : prottab) {
            if ((prot & entry.first)) {
                segprot |= entry.second;
            }
        }
        segment_register(seg->vmaddr, (const void *) ((const char *) file_.map + seg->fileoff),
                         seg->filesize, segprot);
    }
}

void MachOCore::handle_thread(const thread_command *thd) {
    Thread thread;
    const uint32_t *it = (const uint32_t *) (thd + 1);
    while (it < (const uint32_t *) (((const char *) thd + thd->cmdsize))) {
        Thread thread;
        thread.flavor = *it++;
        thread.count = *it++;
        thread.data = (const void *) it;
        it += thread.count;
        threads_.push_back(thread);
    }
}

}
