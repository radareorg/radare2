executable('r2agent', 'r2agent.c',
  include_directories: [platform_inc],
  dependencies: [
    r_util_dep,
    r_main_dep,
    r_socket_dep,
    r_cons_dep
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
