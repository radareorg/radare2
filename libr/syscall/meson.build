files = [
  'syscall.c',
  'ioports.c'
]

r_syscall = library('r_syscall', files,
  include_directories: [platform_inc],
  link_with: [r_util, libr_shlr],
  install: true,
  implicit_include_directories: false
)


pkg = import('pkgconfig')
pkg.generate(libraries: [r_syscall],
             subdirs: 'libr',
             version: r2version,
             name: 'r_syscall',
             filebase: 'r_syscall',
             requires: [
               'r_util'
             ],
             description: 'radare foundation libraries')
