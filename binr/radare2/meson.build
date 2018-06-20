executable('radare2', 'radare2.c',
  include_directories: [platform_inc],
  link_with: [
    r_util, r_socket, r_core, r_io, r_magic, r_fs, r_bin, r_flag, r_cons,
    r_asm, r_debug, r_config, r_bp, r_reg, r_syscall, r_anal, r_parse, r_egg,
    r_search, r_hash, r_crypto,
  ],
  install: true,
  implicit_include_directories: false
)
