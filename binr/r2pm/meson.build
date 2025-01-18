atomic_dep = cc.find_library('atomic', required: false)

executable('r2pm', 'r2pm.c',
  include_directories: [platform_inc],
  dependencies: [atomic_dep, r_util_dep, r_main_dep],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
