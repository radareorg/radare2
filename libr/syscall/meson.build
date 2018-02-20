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
