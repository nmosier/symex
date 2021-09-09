#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <cassert>

namespace cores {

  int open_file(const char *path, void **map, size_t *filelen);

  struct File {
    File(): fd(-1) {}
    File(const char *path): fd(-1) {
      open(path);
    }
    ~File() {
      close();
    }

    bool isopen() const { return fd >= 0; }

    void open(const char *path) {
      close();
      this->path = path;
      fd = open_file(path, &map, &len);
    }

    void close() {
      if (fd >= 0) {
	::close(fd);
	munmap(map, len);
	fd = -1;
      }
    }

    bool operator<(const File& other) const {
      return strcmp(path, other.path) < 0;
    }

    template <typename T>
    const T& at(size_t idx) const {
      assert((idx + 1) * sizeof(T) <= len);
      return ((const T *) map)[idx];
    }
  
    const char *path;
    int fd;
    size_t len;
    void *map;
  };

}
