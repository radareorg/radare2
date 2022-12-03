subdir('d')

r_asm_sources = [
  'asm.c',
  'aop.c',
  'acode.c',
  'parse.c',
  'filter.c',
  'aplugs.c',
  'p/asm_null.c',
]

r_asm_inc = [
  platform_inc,
  include_directories(
    join_paths('..','..','shlr'),
    join_paths('arch','include'),
    join_paths('arch'),
    join_paths('arch','h8300'),
  )
]

if get_option('sdb_cgen')
  r_asm_sources += r_asm_d_sources
endif

r_asm = library('r_asm', r_asm_sources,
  include_directories: r_asm_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_syscall_dep,
    r_lang_dep,
    r_arch_dep,
    r_flag_dep,
    r_socket_dep,
    capstone_dep,
    java_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_asm_dep = declare_dependency(link_with: r_asm,
                               include_directories: r_asm_inc)

if get_option('blob')
r_asm_static = static_library('r_asm_static', r_asm_sources,
  include_directories: r_asm_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_static_dep,
    r_arch_static_dep,
    r_syscall_static_dep,
    r_lang_static_dep,
    r_flag_static_dep,
    r_socket_static_dep,
    capstone_dep,
    java_static_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
)

r_asm_static_dep = declare_dependency(link_with: r_asm_static,
                               include_directories: r_asm_inc)
endif

pkgconfig_mod.generate(r_asm,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_asm',
  filebase: 'r_asm',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_syscall',
    'r_lang',
    'r_flag',
    'r_arch',
    'r_socket'
  ],
  description: 'radare foundation libraries'
)
