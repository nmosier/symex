link_libraries("${Z3_LIBRARIES}" ${CAPSTONE_LIBRARIES} ${LIBPROFILER_LIBRARIES})
link_directories(${CAPSTONE_LIBRARY_DIRS} ${LIBPROFILER_LIBRARY_DIRS})
include_directories("${Z3_INCLUDE_DIRS}"
  ${CAPSTONE_INCLUDE_DIRS}
  ${LIBPROFILER_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}
  )

add_subdirectory(cores)

add_executable(x86-test
  x86.cc x86.h
  x86-test.cc
  explore.cc
  memstate.cc memstate.h
  inst.cc inst.h
  operands.cc operands.h
  archstate.cc archstate.h
  context.cc context.h
  cfg.cc cfg.h
  peephole.h
  program.h
  util.h
  abstract.h abstract.cc
  config.cc config.h
  fpu.cc fpu.h
  value.cc value.h
  $<TARGET_OBJECTS:cores_old>
  )
target_link_libraries(x86-test PRIVATE cores)

if(0)
target_compile_options(x86-test PUBLIC
  -fsanitize=address
  )
target_link_options(x86-test PUBLIC
  -fsanitize=address
  )
endif()
