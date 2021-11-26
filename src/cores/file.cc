#include <cstring>
#include <errno.h>
#include <sys/mman.h>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>

#include "file.hh"

namespace cores {

  int open_file(const char *path, void **map, size_t *filelen) {
    int fd;
    if ((fd = open(path, O_RDONLY)) < 0) {
      fprintf(stderr, "open: %s: %s\n", strerror(errno), path);
      exit(1);
    }
    struct stat sbuf;
    if (fstat(fd, &sbuf) < 0) {
      perror("fstat");
      exit(1);
    }
    *filelen = sbuf.st_size;
    if (*filelen > 0) {
      if ((*map = mmap(nullptr, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
	perror("mmap");
	exit(1);
      }
    }
    return fd;
  }


}
