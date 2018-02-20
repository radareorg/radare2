files = [
  'flag.c',
  'sort.c',
  'spaces.c',
  'zones.c'
]

r_flag = library('r_flag', files,
  include_directories: [platform_inc],
  link_with: [r_util, libr_shlr],
  install: true,
  implicit_include_directories: false
)
