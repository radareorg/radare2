files=[
'syscall.c',
'ioports.c'
]

r_syscall = shared_library('r_syscall', files,
  include_directories: include_directories(['../include']),
  link_with: [r_util],
  install: true
)
