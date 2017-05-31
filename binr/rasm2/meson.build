
executable('rasm2', 'rasm2.c',
  include_directories: [platform_inc],
  link_with: [r_util, r_asm, r_anal, r_syscall],
  objects: [
    libr2sdb.extract_all_objects(),
  ],
  install: true
)
