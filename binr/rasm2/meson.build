executable('rasm2', 'rasm2.c',
  include_directories: [platform_inc],
  dependencies: [
    r_main_dep,
    r_util_dep,
    r_asm_dep,
    r_anal_dep,
    r_crypto_dep,
    r_syscall_dep,
    r_hash_dep,
    sdb_dep
  ],
  install: true,
  install_rpath: get_option('default_library') == 'shared' ? '$ORIGIN/../' + get_option('libdir') : '',
  implicit_include_directories: false
)
