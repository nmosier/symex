project(symex)

cmake_minimum_required(VERSION 3.16)

include(FindPkgConfig)
pkg_check_modules(CAPSTONE REQUIRED capstone)

# find_package(Z3)
set(Z3_LIBRARIES /opt/homebrew/lib/libz3.dylib)
set(Z3_INCLUDE_DIRS /opt/homebrew/include)

set(CMAKE_CXX_STANDARD 17)

link_libraries("${Z3_LIBRARIES}" ${CAPSTONE_LIBRARIES})
link_directories(${CAPSTONE_LIBRARY_DIRS})
include_directories("${Z3_INCLUDE_DIRS}" ${CAPSTONE_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(cores)
add_subdirectory(arch)

add_executable(symex
  symex.cc
  $<TARGET_OBJECTS:arch>
  )
target_compile_options(cores PRIVATE -m32)
target_link_options(cores PRIVATE -m32)
