files = [
  'syscall.c',
  'ioports.c'
]

r_syscall = library('r_syscall', files,
  include_directories: [platform_inc],
  link_with: [
    r_util,
    libr_shlr
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(libraries: [r_syscall],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_syscall',
  filebase: 'r_syscall',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
