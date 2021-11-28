project(symex)

cmake_minimum_required(VERSION 3.16)

include(FindPkgConfig)
pkg_check_modules(CAPSTONE REQUIRED capstone)

pkg_search_module(LIBPROFILER REQUIRED libprofiler)

# find_package(Z3 REQUIRED)
set(Z3_LIBRARIES /opt/homebrew/lib/libz3.dylib)
set(Z3_INCLUDE_DIRS /opt/homebrew/include)

set(CMAKE_CXX_STANDARD 20 REQUIRED)

add_link_options(-w) # no linker warnings

add_subdirectory(cores)
add_subdirectory(src)
