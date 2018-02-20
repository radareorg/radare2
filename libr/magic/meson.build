files = [
  'apprentice.c',
  'ascmagic.c',
  'fsmagic.c',
  'funcs.c',
  'is_tar.c',
  'magic.c',
  # XXX not used? 'print.c',
  'softmagic.c'
]

r_magic = library('r_magic', files,
  include_directories: [platform_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [r_util],
  install: true,
  implicit_include_directories: false
)
