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
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(
  libraries: [r_search],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_search',
  filebase: 'r_search',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
