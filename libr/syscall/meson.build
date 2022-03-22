subdir('d')

r_syscall_sources = [
  'syscall.c',
  'splugs.c',
  'ioports.c'
]

if get_option('sdb_cgen')
  r_syscall_sources += r_syscall_d_sources
endif

r_syscall = library('r_syscall', r_syscall_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_syscall_dep = declare_dependency(link_with: r_syscall, include_directories: [platform_inc])

if get_option('blob')
r_syscall_static = static_library('r_syscall_static', r_syscall_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_static_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
)

r_syscall_static_dep = declare_dependency(link_with: r_syscall_static,
  include_directories: [platform_inc])
endif

pkgconfig_mod.generate(r_syscall,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_syscall',
  filebase: 'r_syscall',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
