#include <cassert>
#include <cstdio>

#include "minidump.hh"

namespace cores {

  void Minidump::parse() {
    assert(file().isopen());

    const MINIDUMP::HEADER *hdr = (const MINIDUMP::HEADER *) file().map;

    if (hdr->Signature != MINIDUMP::SIGNATURE) {
      throw ParseError("not a valid minidump file");
    }

    fprintf(stderr, "StreamDirectoryRva %x\n", hdr->StreamDirectoryRva);
    
    const size_t ndirs = hdr->NumberOfStreams;
    const MINIDUMP::DIRECTORY *dirs =
      (const MINIDUMP::DIRECTORY *) ((const char *) file().map + hdr->StreamDirectoryRva);

    for (size_t i = 0; i < ndirs; ++i) {
      const MINIDUMP::DIRECTORY& dir = dirs[i];
      fprintf(stderr, "dir.Location %x %x\n", dir.Location.DataSize, dir.Location.Rva);
      if (dir.StreamType == MINIDUMP::MemoryListStream || 
	  dir.StreamType == MINIDUMP::Memory64ListStream) {
	parse_memory_list<MINIDUMP::MEMORY_LIST>(dir.Location);
      }
    }
  }

  template <typename MEMORY_LIST>
  void Minidump::parse_memory_list(const MINIDUMP::LOCATION_DESCRIPTOR& loc) {
    const MEMORY_LIST *memlist = at_loc<MEMORY_LIST>(loc);
    const size_t nranges = memlist->NumberOfMemoryRanges;

    /*
      0x101010e09: 0x00000000 0x00201000 0x000138d5 0x2050e000
      0x101010e19: 0x00000000 0x00101000 0x002148d5 0x00098000
    */
    typedef struct {
      uint32_t unused;
      uint32_t len;
      uint32_t off;
      uint32_t vmaddr;
    } MEMORY_DESCRIPTOR;
  
    // assert(loc.DataSize == 16 + sizeof(MINIDUMP::MEMORY_DESCRIPTOR) * nranges);
    for (size_t i = 0; i < nranges; ++i) {
      const MEMORY_DESCRIPTOR& md = (const MEMORY_DESCRIPTOR&) memlist->MemoryRanges[i];
#if 0
      const Segment::ptr_t vmaddr = md.StartOfMemoryRange;
      const void *base = at<void>(md.Memory);
      const size_t len = md.Memory.DataSize;
#else
      const Segment::ptr_t vmaddr = md.vmaddr;
      const void *base = at<void>((size_t) md.off);
      const size_t len = md.len;
#endif
      const prot_t prot = PROT::READ | PROT::WRITE | PROT::EXECUTE;
      // TODO: how to determine perms?
      fprintf(stderr, "vmaddr %llx, base %p, len %zx\n",
	      vmaddr, base, len);
      segment_register(vmaddr, base, len, prot);
    }
  
  }

}
