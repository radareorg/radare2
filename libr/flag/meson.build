
files=[
'flag.c',
'sort.c',
'spaces.c',
'zones.c'
]

r_flag = shared_library('r_flag', files,
  include_directories: include_directories([
  '../include',
  platform_librinc
  ]),
  link_with: [r_util],
  objects: [
    r_sdb.extract_all_objects()
  ],  
  install: true
)

