r_search_sources = [
  'aes_find.c',
  'bytepat.c',
  'keyword.c',
  'regexp.c',
  'uds.c',
  'privkey.c',
  'karp.c',
  'search.c',
  'tire.c',
  'sm4_find.c',
  'strings.c'
]

r_search = library('r_search', r_search_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_muta_dep, r_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_search_dep = declare_dependency(link_with: r_search,
  include_directories: [platform_inc])

if get_option('blob')
r_search_static = static_library('r_search_static', r_search_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_static_dep],
  install: true,
  implicit_include_directories: false,
)

r_search_static_dep = declare_dependency(link_with: r_search_static,
  include_directories: [platform_inc])
endif

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
