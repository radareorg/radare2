r_search_sources = [
  'aes-find.c',
  'bytepat.c',
  'keyword.c',
  'regexp.c',
  'uds.c',
  'privkey-find.c',
  'search.c',
  'strings.c'
]

r_search = library('r_search', r_search_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_search_dep = declare_dependency(link_with: r_search,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(r_search,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_search',
  filebase: 'r_search',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
