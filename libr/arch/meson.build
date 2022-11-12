r_arch_sources = [
  'arch.c',
  'arch_op.c',
  'arch_config.c',
  'arch_switch.c',
  'arch_session.c',
  'arch_cond.c',
  'arch_value.c',
  'p/arch_null.c',
  'p/arch_i4004.c',
  'p/arch_amd29k.c',
  'p/arch_jdh8.c',
  'p/arch_pickle.c',
  'p/arch_sh.c',
  'p/sh/gnu/sh-dis.c',
]

arch_inc = include_directories('../asm/arch/include')

r_arch = library('r_arch', r_arch_sources,
  include_directories: [platform_inc, arch_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_reg_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_arch_dep = declare_dependency(link_with: r_arch,
                              include_directories: [platform_inc])

if get_option('blob')
r_arch_static = static_library('r_arch_static', r_arch_sources,
  include_directories: [platform_inc, arch_inc],
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
    'r_util',
    'r_reg',
  ],
  description: 'radare foundation libraries'
)
