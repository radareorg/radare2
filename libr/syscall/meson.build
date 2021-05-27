r_syscall_sources = [
  'syscall.c',
  'splugs.c',
  'ioports.c'
]

if get_option('sdb_cgen')
  r_syscall_sources += [
    'd/darwin-arm-32.c',
    'd/darwin-arm-64.c',
    'd/darwin-x86-32.c',
    'd/darwin-x86-64.c',
    'd/dos-x86-16.c',
    'd/freebsd-x86-32.c',
    'd/ios-arm-32.c',
    'd/ios-arm-64.c',
    'd/ios-x86-32.c',
    'd/linux-arm-32.c',
    'd/linux-arm-64.c',
    'd/linux-mips-32.c',
    'd/linux-sparc-32.c',
    'd/linux-x86-32.c',
    'd/linux-x86-64.c',
    'd/netbsd-x86-32.c',
    'd/openbsd-x86-32.c',
    'd/openbsd-x86-64.c',
    'd/s110-arm-16.c',
    'd/windows-x86-32.c',
    'd/windows-x86-64.c',
  ]
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

r_syscall_dep = declare_dependency(link_with: r_syscall,
                                   include_directories: [platform_inc])

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
