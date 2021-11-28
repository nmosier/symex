add_library(util_objs OBJECT
  capstone++.h
  )
set_target_properties(util_objs PROPERTIES LINKER_LANGUAGE CXX)
