r_arch_sources = [
  'arch.c',
  'api.c',
# 'p/arch_chungus2.c',
]

r_arch = library('r_arch', r_arch_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_arch_dep = declare_dependency(link_with: r_arch,
                              include_directories: [platform_inc])

if get_option('blob')
r_arch_static = static_library('r_arch_static', r_arch_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_static_dep],
  install: true,
  implicit_include_directories: false,
)

r_arch_static_dep = declare_dependency(link_with: r_arch_static,
  include_directories: [platform_inc])
endif

pkgconfig_mod.generate(r_arch,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_arch',
  filebase: 'r_arch',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
