files = [
  'aes-find.c',
  'bytepat.c',
  'keyword.c',
  # 'old_xrefs.c',
  'regexp.c',
  'rsa-find.c',
  'search.c',
  'strings.c',
  'xrefs.c',
]

r_search = library('r_search', files,
  include_directories: [platform_inc],
  link_with: [r_util],
  install: true,
  implicit_include_directories: false
)


pkg = import('pkgconfig')
pkg.generate(libraries: [r_search],
             subdirs: 'libr',
             version: r2version,
             name: 'r_search',
             filebase: 'r_search',
             requires: [
               'r_util'
             ],
             description: 'radare foundation libraries')
