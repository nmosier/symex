add_library(arch OBJECT
  x86.cc
  )

add_executable(x86-test
  x86.cc
  x86-test.cc
  ../cores/core.cc
  ../cores/macho.cc
  ../cores/minidump.cc
  ../cores/file.cc
  explore.cc
  memstate.cc
  inst.cc
  operands.cc
  archstate.cc
  context.cc
  )
