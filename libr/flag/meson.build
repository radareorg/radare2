
files=[
'flag.c',
'sort.c',
'spaces.c',
'zones.c'
]

r_flag = shared_library('r_flag', files,
  include_directories: [platform_inc],
  link_with: [r_util],
  objects: [
    libr2sdb.extract_all_objects()
  ],  
  install: true
)

