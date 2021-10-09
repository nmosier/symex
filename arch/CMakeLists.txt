add_library(arch OBJECT
  x86.cc
  )

add_executable(x86-test
  x86.cc x86.h
  x86-test.cc
  ../cores/core.cc
  ../cores/macho.cc
  ../cores/minidump.cc
  ../cores/file.cc
  explore.cc
  memstate.cc memstate.h
  inst.cc inst.h
  operands.cc operands.h
  archstate.cc archstate.h
  context.cc context.h
  cfg.cc cfg.h
  peephole.h
  program.h
  ../util.h
  )

if(1)
target_compile_options(x86-test PUBLIC
  -fsanitize=address
  )
target_link_options(x86-test PUBLIC
  -fsanitize=address
  )
endif()
