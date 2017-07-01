files=[
'syscall.c',
'ioports.c'
]

r_syscall = library('r_syscall', files,
  include_directories: [platform_inc],
  link_with: [r_util],
  objects: [
	libr2sdb.extract_all_objects()
  ],
  install: true
)
