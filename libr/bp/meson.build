r_bp_sources = [
  'bp.c',
  'bp_io.c',
  'bp_plugin.c',
  'bp_traptrace.c',
  'bp_watch.c',
  'p/bp_arm.c',
  'p/bp_bf.c',
  'p/bp_mips.c',
  'p/bp_ppc.c',
  'p/bp_sh.c',
  'p/bp_x86.c'
]

r_bp = library('r_bp', r_bp_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_bp_dep = declare_dependency(link_with: r_bp,
                              include_directories: [platform_inc])

pkgconfig_mod.generate(r_bp,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_bp',
  filebase: 'r_bp',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
