r_esil_sources = [
  'esil.c',
  'esil_handler.c',
  'esil_plugin.c',
  'esil_stats.c',
  'esil_compiler.c',
  'esil_trace.c',
  'esil_toc.c',
  'p/esil_null.c',
  'p/esil_forth.c',
  'p/esil_dummy.c',
]
esil_extra_inc = include_directories('..', '../include')

r_esil = library('r_esil', r_esil_sources,
  include_directories: [platform_inc, esil_extra_inc, sdb_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    sdb_dep,
    r_reg_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)


r_esil_dep = declare_dependency(link_with: r_esil,
                              include_directories: [platform_inc, esil_extra_inc, sdb_inc])

if get_option('blob')
r_esil_static = static_library('r_esil_static', r_esil_sources,
  include_directories: [platform_inc, sdb_inc, esil_extra_inc],
  c_args: library_cflags,
  dependencies: [r_util_static_dep],
  install: true,
  implicit_include_directories: false,
)

r_esil_static_dep = declare_dependency(link_with: r_esil_static,
  include_directories: [platform_inc, esil_extra_inc, sdb_inc])
endif

pkgconfig_mod.generate(r_esil,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_esil',
  filebase: 'r_esil',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_reg',
  ],
  description: 'radare foundation libraries'
)
