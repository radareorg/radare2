r_magic_sources = [
  'apprentice.c',
  'ascmagic.c',
  'fsmagic.c',
  'funcs.c',
  'is_tar.c',
  'magic.c',
  # XXX not used? 'print.c',
  'softmagic.c'
]

r_magic_deps = [r_util_dep]
if use_syslib_magic
  message('Use system-provided magic library')
  r_magic_deps += [sys_magic]
else
  message('Use bundled magic library')
endif

r_magic = library('r_magic', r_magic_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: r_magic_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_magic_dep = declare_dependency(
  link_with: r_magic,
  include_directories: platform_inc
)

pkgconfig_mod.generate(r_magic,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_magic',
  filebase: 'r_magic',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
pkgconfig_magic_requires = ['r_magic']
