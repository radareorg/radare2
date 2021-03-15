executable('rahash2', 'rahash2.c',
  include_directories: [platform_inc],
  dependencies: [
    r_util_dep,
    r_main_dep,
    r_hash_dep,
    r_io_dep,
    r_crypto_dep,
    r_socket_dep
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
