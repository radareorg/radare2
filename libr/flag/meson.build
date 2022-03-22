r_flag_sources = [
  'flag.c',
  'tags.c',
  'zones.c'
]

r_flag = library('r_flag', r_flag_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_flag_dep = declare_dependency(link_with: r_flag,
                                include_directories: [platform_inc])

if get_option('blob')
r_flag_static = static_library('r_flag_static', r_flag_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_static_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
)

r_flag_static_dep = declare_dependency(link_with: r_flag_static,
                                include_directories: [platform_inc])
endif

pkgconfig_mod.generate(r_flag,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_flag',
  filebase: 'r_flag',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
