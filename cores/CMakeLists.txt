add_library(cores STATIC
  core.cc
  macho.cc
  minidump.cc
  file.cc
  )
target_compile_options(cores PRIVATE -m32)
target_link_options(cores PRIVATE -m32)
