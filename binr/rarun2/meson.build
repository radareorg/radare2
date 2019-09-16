executable('rarun2', 'rarun2.c',
  include_directories: [platform_inc],
  dependencies: [
    r_main_dep,
    r_util_dep,
    r_socket_dep
  ],
  install: true,
  install_rpath: get_option('default_library') == 'shared' ? '$ORIGIN/../' + get_option('libdir') : '',
  implicit_include_directories: false
)
