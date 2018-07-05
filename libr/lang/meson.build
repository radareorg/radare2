files = [
  'lang.c',
  'p/c.c',
  #'p/cpipe.c',
  'p/lib.c',
  'p/pipe.c',
  'p/rust.c',
  'p/vala.c'
]

r_lang = library('r_lang', files,
  include_directories: [platform_inc],
  c_args: ['-DCORELIB=1'],
  dependencies: [r_util_dep, r_cons_dep],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_lang_dep = declare_dependency(link_with: r_lang,
			        include_directories: [platform_inc])

pkgconfig_mod.generate(
  libraries: [r_lang],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_lang',
  filebase: 'r_lang',
  requires: [
    'r_util',
    'r_cons'
  ],
  description: 'radare foundation libraries'
)
