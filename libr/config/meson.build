r_config_sources = [
  'callback.c',
  'config.c',
  'hold.c',
]

r_config = library('r_config', r_config_sources,
  include_directories: [platform_inc],
  dependencies: [
    r_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_config_dep = declare_dependency(link_with: r_config,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(r_config,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_config',
  filebase: 'r_config',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
