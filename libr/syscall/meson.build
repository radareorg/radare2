files=[
'syscall.c',
'ioports.c'
]

r_syscall = shared_library('r_syscall', files,
  include_directories: include_directories([
  '../include'],
  platform_librinc
  ),
  link_with: [r_util],
  objects: [
    r_sdb.extract_all_objects()
  ],
  install: true
)
