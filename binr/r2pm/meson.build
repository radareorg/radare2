install_data('r2pm.sh', install_dir: get_option('bindir'))
executable('r2pm', 'r2pm.c',
  include_directories: [platform_inc],
  dependencies: [r_util_dep, r_main_dep],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
