w32dbg_wrap_inc = include_directories('include')
w32dbg_wrap_src = ['src/w32dbg_wrap.c']
w32dbg_wrap_lib = static_library(
  'r2w32dbg_wrap',
  w32dbg_wrap_src,
  include_directories : w32dbg_wrap_inc,
)
w32dbg_wrap_dep = declare_dependency(
  link_with : w32dbg_wrap_lib,
  include_directories: w32dbg_wrap_inc,
)
