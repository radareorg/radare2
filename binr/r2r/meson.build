
if get_option('enable_r2r')
  executable('r2r', ['r2r.c', 'load.c', 'run.c'],
    include_directories: [platform_inc],
    dependencies: [
      r_util_dep,
      lrt,
    ],
    install: true,
    install_rpath: rpath_exe,
    implicit_include_directories: false
  )
endif
