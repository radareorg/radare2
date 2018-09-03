files = [
  'egg.c',
  'egg_Cfile.c',
  'egg_lang.c',
  'emit_arm.c',
  'emit_trace.c',
  'emit_x64.c',
  'emit_x86.c',
  #'p/egg_bind.c',
  #'p/egg_cb.c',
  'p/egg_exec.c',
  #'p/egg_reverse.c',
  #'p/egg_shya.c',
  'p/egg_xor.c'
]

r_egg = library('r_egg', files,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_asm_dep,
    r_syscall_dep,
    sdb_dep
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_egg_dep = declare_dependency(link_with: r_egg,
                               include_directories: [platform_inc])

pkgconfig_mod.generate(
  libraries: [r_egg],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_egg',
  filebase: 'r_egg',
  requires: [
    'r_util',
    'r_asm',
    'r_syscall'
  ],
  description: 'radare foundation libraries'
)
