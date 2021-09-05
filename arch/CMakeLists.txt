add_library(arch OBJECT
  x86.cc
  )

add_executable(x86-test
  x86.cc
  x86-test.cc
  )
