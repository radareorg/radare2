executable('rafind2', 'rafind2.c',
  include_directories: [platform_inc],
  dependencies: [
    r_main_dep,
    r_util_dep,
    r_search_dep,
    r_crypto_dep,
    r_io_dep,
    r_main_dep,
    r_cons_dep
  ],
  install: true,
  install_rpath: get_option('default_library') == 'shared' ? '$ORIGIN/../' + get_option('libdir') : '',
  implicit_include_directories: false
)
