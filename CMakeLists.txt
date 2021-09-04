project(symex)

cmake_minimum_required(VERSION 3.16)

# find_package(Z3)
set(Z3_LIBRARIES /usr/local/lib/libz3.dylib)
set(Z3_INCLUDE_DIRS /usr/local/include)

set(CMAKE_CXX_STANDARD 17)

add_executable(symex
  symex.cc
  )
target_link_libraries(symex PRIVATE "${Z3_LIBRARIES}")
target_include_directories(symex PRIVATE "${Z3_INCLUDE_DIRS}")
# target_compile_options(symex PRIVATE -m32)
# target_link_options(symex PRIVATE -m32)
