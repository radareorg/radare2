files=[
'apprentice.c',
'ascmagic.c',
'fsmagic.c',
'funcs.c',
'is_tar.c',
'magic.c',
# XXX not used? 'print.c',
'softmagic.c'
]

r_magic = shared_library('r_magic', files,
  include_directories: include_directories([
  '../include'],
  platform_librinc
  ),
  c_args: ['-DCORELIB','-DHAVE_CONFIG_H','-I.'],
  link_with: [r_util],
  install: true
)
