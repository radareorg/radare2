files = [
  'lang.c',
  'p/c.c',
  # 'p/cpipe.c',
  'p/lib.c',
  'p/pipe.c',
  'p/rust.c',
  'p/vala.c'
]

r_lang = library('r_lang', files,
  include_directories: [platform_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [r_util, r_cons],
  install: true,
  implicit_include_directories: false
)
